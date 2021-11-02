#include <bits/stdc++.h>
#include "ns3/aodv-helper.h"
#include "ns3/aodv-routing-protocol.h"
#include "ns3/aodv-rtable.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/wifi-module.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("MyCode");

double kProbContinue = 50; // %
double kProbNew = 50;
// Node::kNodeFlag::FLAG_NORMAL = 0;
// Node::kNodeFlag::FLAG_PROBE = 1;
// Node::kNodeFlag::FLAG_DEFEND = 2;
uint32_t kProbePort = 2333;
uint32_t kProbeTtl = 4;
uint32_t kDefendTtl = 4;
uint32_t kPacketSize = 1 << 10;
uint32_t kMaxPacketsEverySeconds = 50;  // 每秒至多发1个包
// 每1s更新一次
double kUpdateTime = 0.5;
uint32_t kAttackerRate = kMaxPacketsEverySeconds * 4;
uint32_t kClientRate = 2;
using filterPair =
    std::pair<Ipv4Address, Ipv4Address>;  // suspicious path: Attacker>>Victim
class MyTag : public Tag {
 public:
  static TypeId GetTypeId(void);
  virtual TypeId GetInstanceTypeId(void) const;
  virtual uint32_t GetSerializedSize(void) const;
  virtual void Serialize(TagBuffer i) const;
  virtual void Deserialize(TagBuffer i);
  virtual void Print(std::ostream &os) const;

  void SetFlag(uint32_t value);
  uint32_t GetFlag(void) const;
  void SetFlagTtl(uint32_t ttl);
  uint32_t GetFlagTtl(void) const;
  void SetPid(uint32_t pid);
  uint32_t GetPid(void) const;
  void SetFilterPairs(std::set<filterPair> filterpairs);
  std::set<filterPair> GetFilterPairs(void);

 private:
  uint32_t m_flag;
  uint32_t m_ttl;
  uint32_t m_pid;
  std::set<filterPair> m_filterpairs;
};
std::ostream &operator<<(std::ostream &os, MyTag const &mytag) {
  mytag.Print(os);
  return os;
}

std::set<Ipv4Address> Sclientip;
uint32_t cnt_recvnormalpacket;
//模拟服务器接受，每隔一段时间(1s)统一接受，利用套接字缓冲队列溢出模拟服务器处理能力
void RecvNormal(Ptr<Socket> sock);
void RecvProbeCallback(Ptr<Socket> sock);
void SendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl, uint32_t pid,
                       std::set<filterPair> filterpairs);
// 对特定ip进行流量监测
void ThroughputMonitor(FlowMonitorHelper *flowMonitorHelper,
                       Ptr<FlowMonitor> flowMonitor, Ptr<Socket> sock,
                       std::map<FlowId, uint32_t> &rxMP);
void printkNodeFlag(NodeContainer nodes) {
  std::stringstream stmp;
  for (uint32_t i = 0; i < nodes.GetN(); i++)
    stmp << nodes.Get(i)->GetFlag() << " ";
  // NS_LOG_DEBUG(stmp.str());
}

int main(int argc, char *argv[]) {
  Time::SetResolution(Time::NS);

  // LogComponentEnable("MyCode", LOG_LEVEL_INFO);
  // LogComponentEnable ("TcpL4Protocol", LOG_LEVEL_INFO);
  // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  // LogComponentEnable("AodvRoutingTable", LOG_LEVEL_ALL);
  // LogComponentEnable("UdpSocketImpl", LOG_LEVEL_ALL);
  // LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("Node", LOG_LEVEL_INFO);
  // LogComponentEnable("PacketSink", LOG_LEVEL_ALL);

  uint32_t nAdHocNum = 60;
  uint32_t nStep = 50;
  uint32_t nNs3Seed = 6;
  uint32_t nSrandSeed = (unsigned)time(nullptr);
  uint32_t nOutFileId = 0;

  CommandLine cmd;
  cmd.AddValue("nAdHocNum", "Number of wifi ad devices", nAdHocNum);
  cmd.AddValue("nStep", "distance between two node", nStep);
  cmd.AddValue("nNs3Seed", "ns3 random seed", nNs3Seed);
  cmd.AddValue("nSrandSeed", "c++ random seed", nSrandSeed);
  cmd.AddValue("nOutFileId", "nOutFileId", nOutFileId);
  cmd.AddValue("kProbContinue", "kProbContinue p%", kProbContinue);
  cmd.AddValue("kProbNew", "kProbNew p%", kProbNew);
  cmd.AddValue("kProbeTtl", "kProbeTtl", kProbeTtl);
  cmd.AddValue("kDefendTtl", "kDefendTtl", kDefendTtl);
  cmd.AddValue("kPacketSize", "kPacketSize", kPacketSize);
  cmd.AddValue("kPacketMaxSpeed", "kPacketMaxSpeed", kMaxPacketsEverySeconds);
  cmd.AddValue("kUpdateTime", "kUpdateTime", kUpdateTime);
  cmd.Parse(argc, argv);
  kProbContinue/=100.;
  kProbNew/=100.;
  // srand((unsigned)time(nullptr));
  srand(nSrandSeed);

  NodeContainer adhoc_nodes;
  adhoc_nodes.Create(nAdHocNum);
  for (uint32_t i = 0; i < nAdHocNum; ++i) {
    std::ostringstream os;
    os << "node-" << i;
    Names::Add(os.str(), adhoc_nodes.Get(i));
    adhoc_nodes.Get(i)->SetFlagValidTime(Seconds(kUpdateTime * 10.));
    adhoc_nodes.Get(i)->SetSuspiciousValidTime(Seconds(kUpdateTime * 9.));
    adhoc_nodes.Get(i)->SetAttackerValidTime(Seconds(kUpdateTime * 8.));
    uint32_t tmp = (uint32_t)(kUpdateTime * 8. * kMaxPacketsEverySeconds);
    adhoc_nodes.Get(i)->SetAttackerThrsh(tmp);
    adhoc_nodes.Get(i)->SetAttackerProb(1. / tmp);
  }

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetPcapDataLinkType(YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  phy.SetChannel(channel.Create());

  WifiHelper wifi;
  // wifi.SetStandard(WIFI_PHY_STANDARD_80211a); //设置标准
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
                               StringValue("OfdmRate6Mbps"));

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer adhoc_devices;
  adhoc_devices = wifi.Install(phy, mac, adhoc_nodes);

  MobilityHelper mobility;
  RngSeedManager::SetSeed(nNs3Seed);
  mobility.SetPositionAllocator(
      "ns3::RandomRectanglePositionAllocator", "X",
      StringValue("ns3::UniformRandomVariable[Min=0|Max=250]"), "Y",
      StringValue("ns3::UniformRandomVariable[Min=0|Max=250]"));
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(adhoc_nodes);

  AodvHelper aodv;
  aodv.Set("HelloInterval", TimeValue(Seconds(2.)));
  Ipv4StaticRoutingHelper static_routing;
  Ipv4ListRoutingHelper list;
  list.Add(static_routing, 0);
  list.Add(aodv, 10);
  InternetStackHelper internet;
  internet.SetRoutingHelper(list);
  internet.Install(adhoc_nodes);

  Ipv4AddressHelper address;
  address.SetBase("195.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer adhoc_ipv4;
  adhoc_ipv4 = address.Assign(adhoc_devices);

  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowMonitorHelper;
  flowMonitor = flowMonitorHelper.Install(adhoc_nodes);

  uint32_t normalport = 108;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for (uint32_t i = 0; i < adhoc_nodes.GetN(); i++) {
    Ptr<Socket> recvProbeSocket = Socket::CreateSocket(adhoc_nodes.Get(i), tid);
    recvProbeSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), kProbePort));
    recvProbeSocket->SetRecvCallback(MakeCallback(&RecvProbeCallback));
    Simulator::Schedule(Seconds(1e-9), ThroughputMonitor, &flowMonitorHelper,
                        flowMonitor, recvProbeSocket,
                        std::map<FlowId, uint32_t>{});
  }

  double total_time = 20.0;
  double send_time = 10.0;
  uint32_t recvid = 31;
  std::default_random_engine rng(nSrandSeed);
  std::uniform_real_distribution<double> uni(0., 2e-3);
  OnOffHelper onOffAttack(
      "ns3::UdpSocketFactory",
      Address(InetSocketAddress(adhoc_ipv4.GetAddress(recvid), normalport)));
  // SetConstantRate必须放前面
  onOffAttack.SetConstantRate(DataRate((kPacketSize << 3) * kAttackerRate),
                              kPacketSize);
  onOffAttack.SetAttribute(
      "OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
  onOffAttack.SetAttribute(
      "OffTime", StringValue("ns3::UniformRandomVariable[Min=0|Max=0.02]"));

  NodeContainer attackers;
  {
    vector<uint32_t> V{4,35,20,0,40,24};
    shuffle(V.begin(), V.end(), rng);
    for (auto x:V)
      attackers.Add(adhoc_nodes.Get(x));
  }
  ApplicationContainer appAttacker = onOffAttack.Install(attackers);
  appAttacker.Start(Seconds(1.5 + uni(rng)));
  appAttacker.Stop(Seconds(1.5 + send_time));

  OnOffHelper onOffClient(
      "ns3::UdpSocketFactory",
      Address(InetSocketAddress(adhoc_ipv4.GetAddress(recvid), normalport)));
  // SetConstantRate必须放前面
  onOffClient.SetConstantRate(DataRate((kPacketSize << 3) * kClientRate),
                              kPacketSize);
  onOffClient.SetAttribute(
      "OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
  onOffClient.SetAttribute(
      "OffTime", StringValue("ns3::UniformRandomVariable[Min=0|Max=0.1]"));

  NodeContainer clients;
  {
    vector<uint32_t> V{34,48,33,13,56,10};
    shuffle(V.begin(), V.end(), rng);
    for (auto x:V){
      clients.Add(adhoc_nodes.Get(x));
      Sclientip.insert(adhoc_ipv4.GetAddress(x));
    }
  }
  ApplicationContainer appClient = onOffClient.Install(clients);
  appClient.Start(Seconds(1.6 + uni(rng)));
  appClient.Stop(Seconds(1.5 + send_time));

  // PacketSinkHelper sinkHelper ("ns3::UdpSocketFactory",
  // Address(InetSocketAddress (Ipv4Address::GetAny(), normalport)));
  // ApplicationContainer appRecv = sinkHelper.Install(adhoc_nodes.Get(recvid));
  // appRecv.Start(Seconds(0.0));
  // appRecv.Stop(Seconds(total_time));

  Ptr<Socket> recvsocket = Socket::CreateSocket(adhoc_nodes.Get(recvid), tid);
  recvsocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), normalport));
  recvsocket->SetAttribute(
      "RcvBufSize", UintegerValue(kPacketSize * kMaxPacketsEverySeconds));
  Simulator::Schedule(Seconds(1e-9), &RecvNormal, recvsocket);

  // phy.EnablePcap("rgg2", adhoc_devices);
  // Ptr<OutputStreamWrapper> routingStream =
  // Create<OutputStreamWrapper>("rgg2.routes", std::ios::out);
  // aodv.PrintRoutingTableAllEvery(Seconds(1), routingStream);

  Simulator::Stop(Seconds(total_time));
  Simulator::Run();

  std::stringstream flowmonfile;
  flowmonfile.precision(2);
  flowmonfile << "./rgg2data/test2_" << std::setiosflags(ios::fixed) << kProbContinue << "_" 
              << std::setiosflags(ios::fixed) <<  kProbNew << "_" << nOutFileId << ".flowmon";
  // flowMonitor->SerializeToXmlFile(flowmonfile.str(), false, false);

  {
    std::map<FlowId, FlowMonitor::FlowStats> flowStats =
        flowMonitor->GetFlowStats();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper.GetClassifier());
    std::stringstream flowmonfile_simple;
    flowmonfile_simple.precision(2);
    flowmonfile_simple << "./test_" << std::setiosflags(ios::fixed) << kProbContinue << "_" 
                       << std::setiosflags(ios::fixed) << kProbNew << "_" << nOutFileId << ".out";
    std::ofstream outfile(flowmonfile_simple.str());
    std::map<Ipv4Address, string> MP;
    std::vector<uint32_t> V;
    V.push_back(4), V.push_back(35), V.push_back(20);
    V.push_back(0), V.push_back(40), V.push_back(24);
    V.push_back(34), V.push_back(48), V.push_back(33);
    V.push_back(13), V.push_back(56), V.push_back(10);
    // V.push_back(1), V.push_back(22), V.push_back(44);
    uint32_t txcnt = 0, rxcnt = 0;
    for (auto item : flowStats) {
      // FiveTuple五元组是：(source-ip, destination-ip, protocol, source-port,
      // destination-port)
      auto tmp = classifier->FindFlow(item.first);
      if (tmp.destinationAddress == adhoc_ipv4.GetAddress(recvid) &&
          tmp.destinationPort == normalport) {
        //
        std::stringstream ss;
        ss << tmp.sourceAddress << " >>> " << tmp.destinationAddress << ": ";
        ss << item.second.txPackets << "/" << item.second.rxPackets;
        MP[tmp.sourceAddress] = ss.str();
        if (item.second.txPackets < 200) {
          txcnt += item.second.txPackets;
          rxcnt += item.second.rxPackets;
        }
      }
    }
    for (auto x : V) outfile << MP[adhoc_ipv4.GetAddress(x)] << std::endl;
    outfile << "Ip layer total receive/send: " << 100. * rxcnt / txcnt << "%"
            << std::endl;
    outfile << "Socket(server) total receive/send: "
            << 100. * cnt_recvnormalpacket / txcnt << "%" << std::endl;
    outfile.close();
  }
  Simulator::Destroy();

  return 0;
}

void RecvNormal(Ptr<Socket> sock) {
  NS_LOG_DEBUG(Now().GetSeconds() << "s, Normal");
  std::cout << Now().GetSeconds() << "s, Normal" << std::endl;
  Address org_src;
  Ptr<Packet> packet;
  while (packet = sock->RecvFrom(org_src)) {
    InetSocketAddress inet_src = InetSocketAddress::ConvertFrom(org_src);
    NS_LOG_DEBUG("received a normal packet from " << inet_src.GetIpv4() << " "
                                                  << inet_src.GetPort());
    std::cout << "received a normal packet from " << inet_src.GetIpv4() << " "
              << inet_src.GetPort() << std::endl;
    if (Sclientip.find(inet_src.GetIpv4()) != Sclientip.end())
      cnt_recvnormalpacket++;
  }
  Simulator::Schedule(Seconds(1.0), &RecvNormal, sock);
}

void RecvProbeCallback(Ptr<Socket> sock) {
  NS_LOG_DEBUG("Probe Callback");
  Address org_src;
  Ptr<Packet> packet = sock->RecvFrom(org_src);
  InetSocketAddress inet_src = InetSocketAddress::ConvertFrom(org_src);

  MyTag org_tag;
  packet->PeekPacketTag(org_tag);

  NS_LOG_DEBUG("node name: " << Names::FindName(sock->GetNode()));
  NS_LOG_DEBUG("received a special packet from " << inet_src.GetIpv4() << " "
                                                 << inet_src.GetPort());
  NS_LOG_DEBUG(org_tag);

  Ptr<Node> node = sock->GetNode();
  if (node->IsReceivedPid(org_tag.GetPid())) return;
  node->AddReceivedPid(org_tag.GetPid());

  Ptr<Ipv4L3Protocol> ipl3p = node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
  Ptr<aodv::RoutingProtocol> aodv_rtp =
      AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
  aodv::RoutingTable aodv_rtt = aodv_rtp->GetRoutingTable();
  std::default_random_engine rng(rand());
  std::uniform_real_distribution<double> uni(0., 2e-3);
  if (org_tag.GetFlag() != Node::kNodeFlag::FLAG_NORMAL) {
    // if (node->GetFlag() == Node::kNodeFlag::FLAG_NORMAL) {
    if (1) {
      auto mp = aodv_rtt.GetMap();
      set<Ipv4Address> tmp;
      for (auto item : mp) {
        aodv::RoutingTableEntry rtte = item.second;
        // Ipv4Address dst = item.first;
        // NS_LOG_DEBUG("dst: " << dst << ", rtte next hop: " <<
        // rtte.GetNextHop());
        Ipv4Address nexthop = rtte.GetNextHop();
        if (nexthop.IsLocalhost() || nexthop.IsBroadcast() ||
            nexthop.IsSubnetDirectedBroadcast(Ipv4Mask("255.255.255.0")) ||
            nexthop == inet_src.GetIpv4())
          continue;

        // send probe packet to neighbor
        // || (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
        // org_tag.GetFlagTtl() == kProbeTtl + 1)
        if ((1.0 * rand() / RAND_MAX < kProbContinue &&
             org_tag.GetFlagTtl() > 1)) {
          if (tmp.find(nexthop) != tmp.end()) continue;
          tmp.insert(nexthop);
          NS_LOG_DEBUG(Now() << " send Origin packet to " << nexthop);
          Simulator::Schedule(Seconds(uni(rng)), SendSpecialPacket, sock,
                              InetSocketAddress(nexthop, kProbePort),
                              org_tag.GetFlag(), org_tag.GetFlagTtl() - 1,
                              org_tag.GetPid(), org_tag.GetFilterPairs());
        }
        // send new defend packet to neighbor
        if (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
            1.0 * rand() / RAND_MAX < kProbNew) {
          if (tmp.find(nexthop) != tmp.end()) continue;
          tmp.insert(nexthop);
          NS_LOG_DEBUG(Now() << " send Defend packet to " << nexthop);
          Simulator::Schedule(Seconds(uni(rng)), SendSpecialPacket, sock,
                              InetSocketAddress(nexthop, kProbePort),
                              Node::kNodeFlag::FLAG_DEFEND, kDefendTtl,
                              org_tag.GetPid(), org_tag.GetFilterPairs());
        }
      }
      tmp.clear();
    }
    // 检测节点
    if (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
        org_tag.GetFlagTtl() == kProbeTtl + 1)
      return;
    if (node->GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
        org_tag.GetFlag() == Node::kNodeFlag::FLAG_DEFEND)
      node->SetFlag(Node::kNodeFlag::FLAG_PROBE);  // 关键结点，延长时间
    else
      node->SetFlag(org_tag.GetFlag());
    for (auto item : org_tag.GetFilterPairs()) node->AddSuspect(item);
  } else {
    // normal packet
    NS_LOG_DEBUG("???");
  }
}

void SendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl, uint32_t pid,
                       std::set<filterPair> filterpairs) {
  Ptr<Packet> p = Create<Packet>();
  // create a tag.
  MyTag tag;
  tag.SetFlag(flag);
  tag.SetFlagTtl(ttl);
  tag.SetPid(pid);
  tag.SetFilterPairs(filterpairs);
  p->AddPacketTag(tag);

  sock->SendTo(p, 0, dst);
}

void ThroughputMonitor(FlowMonitorHelper *flowMonitorHelper,
                       Ptr<FlowMonitor> flowMonitor, Ptr<Socket> sock,
                       std::map<FlowId, uint32_t> &rxMP) {
  // NS_LOG_DEBUG(Now() << " Monitor " << Names::FindName(sock->GetNode()));
  flowMonitor->CheckForLostPackets();
  std::map<FlowId, FlowMonitor::FlowStats> flowStats =
      flowMonitor->GetFlowStats();
  Ptr<Ipv4FlowClassifier> classifier =
      DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper->GetClassifier());
  Ptr<Ipv4> ipv4 = sock->GetNode()->GetObject<Ipv4>();
  Ipv4Address nodeip = ipv4->GetAddress(1, 0).GetLocal();
  uint32_t num = 0;
  set<Ipv4Address> S;
  for (auto item : flowStats) {
    // FiveTuple五元组是：(source-ip, destination-ip, protocol, source-port,
    // destination-port)
    auto tmp = classifier->FindFlow(item.first);
    // a flow other >>> node
    if (tmp.destinationAddress == nodeip &&
        tmp.destinationPort != aodv::RoutingProtocol::AODV_PORT) {
      // 流量监测
      uint32_t delta = item.second.rxPackets - rxMP[item.first];
      num += delta;
      // NS_LOG_DEBUG(tmp.destinationAddress);
      // NS_LOG_DEBUG(item.second.rxPackets << " " <<rxMP[item.first]);
      if (delta) S.insert(tmp.sourceAddress);
      rxMP[item.first] = item.second.rxPackets;
    }
  }
  if (num > (uint32_t)(kUpdateTime * kMaxPacketsEverySeconds)) {
    std::set<filterPair> S1;
    for (auto item : S) {
      NS_LOG_DEBUG("suspicious path: " << item << " >> " << nodeip);
      S1.insert(std::make_pair(item, nodeip));
    }
    Simulator::ScheduleNow(SendSpecialPacket, sock,
                           InetSocketAddress(nodeip, kProbePort),
                           Node::kNodeFlag::FLAG_PROBE, kProbeTtl + 1, rand(),
                           S1);  // 因为向自己发包故+1
  }
  Simulator::Schedule(Seconds(kUpdateTime), &ThroughputMonitor,
                      flowMonitorHelper, flowMonitor, sock, rxMP);
}

TypeId MyTag::GetTypeId(void) {
  static TypeId tid =
      TypeId("ns3::MyTag")
          .SetParent<Tag>()
          .AddConstructor<MyTag>()
          .AddAttribute("FlagValue", "packet flag value", EmptyAttributeValue(),
                        MakeUintegerAccessor(&MyTag::GetFlag),
                        MakeUintegerChecker<uint32_t>())
          .AddAttribute("FlagTtlValue", "packet Flag Ttl",
                        EmptyAttributeValue(),
                        MakeUintegerAccessor(&MyTag::GetFlagTtl),
                        MakeUintegerChecker<uint32_t>());
  return tid;
}
TypeId MyTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t MyTag::GetSerializedSize(void) const {
  return sizeof(uint32_t) * 2 +
         sizeof(uint32_t) * (2 * m_filterpairs.size() + 1);
}
void MyTag::Serialize(TagBuffer buffer) const {
  buffer.WriteU32(m_flag);
  buffer.WriteU32(m_ttl);
  uint32_t num = m_filterpairs.size();
  buffer.WriteU32(num);
  uint32_t ip;
  for (auto item : m_filterpairs) {
    ip = item.first.Get();
    for (int i = 3; i >= 0; i--) {
      // NS_LOG_DEBUG(((ip >> (8 * i)) & 0xff));
      buffer.WriteU8((ip >> (8 * i)) & 0xff);
    }
    ip = item.second.Get();
    for (int i = 3; i >= 0; i--) buffer.WriteU8((ip >> (8 * i)) & 0xff);
  }
}
void MyTag::Deserialize(TagBuffer buffer) {
  m_flag = buffer.ReadU32();
  m_ttl = buffer.ReadU32();
  uint32_t num = buffer.ReadU32();
  m_filterpairs.clear();
  uint32_t ip;
  for (uint32_t k = 0; k < num; k++) {
    filterPair tmp;
    ip = 0;
    for (int i = 0; i < 4; i++) ip <<= 8, ip |= buffer.ReadU8();
    tmp.first.Set(ip);
    ip = 0;
    for (int i = 0; i < 4; i++) ip <<= 8, ip |= buffer.ReadU8();
    tmp.second.Set(ip);
    m_filterpairs.insert(tmp);
  }
}
void MyTag::Print(std::ostream &os) const {
  os << "flag: " << m_flag << ", ttl: " << m_ttl
     << ", filterPairs: " << std::endl;
  for (auto item : m_filterpairs)
    os << item.first << " >>> " << item.second << std::endl;
}
void MyTag::SetFlag(uint32_t value) { m_flag = value; }
uint32_t MyTag::GetFlag(void) const { return m_flag; }
void MyTag::SetFlagTtl(uint32_t ttl) { m_ttl = ttl; }
uint32_t MyTag::GetFlagTtl(void) const { return m_ttl; }
void MyTag::SetPid(uint32_t pid) { m_pid = pid; }
uint32_t MyTag::GetPid(void) const { return m_pid; }
void MyTag::SetFilterPairs(std::set<filterPair> pirs) { m_filterpairs = pirs; }
std::set<filterPair> MyTag::GetFilterPairs(void) { return m_filterpairs; }
