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
#include "ns3/wifi-module.h"
#include "ns3/on-off-helper.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("MyCode");

double kProbContinue = 0.5;
double kProbNew = 0.5;
//Node::kNodeFlag::FLAG_NORMAL = 0;
//Node::kNodeFlag::FLAG_PROBE = 1;
//Node::kNodeFlag::FLAG_DEFEND = 2;
uint32_t kProbePort = 2333;
uint32_t kProbeTtl = 4;
uint32_t kDefendTtl = 4;
uint32_t kPacketSize = 1<<10;
uint32_t kMaxPacketsEverySeconds = 50;  // 每秒至多发1个包
// 每1s更新一次
double kUpdateTime = 0.5;
uint32_t kAttackerRate = kMaxPacketsEverySeconds*4;
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
std::ostream& operator<< (std::ostream& os, MyTag const& mytag){
  mytag.Print(os);
  return os;
}

static void recvProbeCallback(Ptr<Socket> sock);
static void recvNormalCallback(Ptr<Socket> sock);
void sendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl,uint32_t pid, std::set<filterPair> filterpairs);
void sendNormalPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t numPackets, Time interval);
// 对特定ip进行流量监测
void ThroughputMonitor(FlowMonitorHelper *flowMonitorHelper,
                       Ptr<FlowMonitor> flowMonitor, Ptr<Socket> sock,
                       std::map<FlowId, uint32_t> &rxMP);
void ChangeRecvBuffSize(Ptr<Application> app, uint32_t siz);
void printkNodeFlag(NodeContainer nodes){
    std::stringstream stmp;
    for(uint32_t i = 0;i < nodes.GetN(); i++) stmp << nodes.Get(i)->GetFlag() << " ";
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
  cmd.AddValue("kProbContinue", "kProbContinue", kProbContinue);
  cmd.AddValue("kProbNew", "kProbNew", kProbNew);
  cmd.AddValue("kProbeTtl", "kProbeTtl", kProbeTtl);
  cmd.AddValue("kDefendTtl", "kDefendTtl", kDefendTtl);
  cmd.AddValue("kPacketSize", "kPacketSize", kPacketSize);
  cmd.AddValue("kPacketMaxSpeed", "kPacketMaxSpeed", kMaxPacketsEverySeconds);
  cmd.AddValue("kUpdateTime", "kUpdateTime", kUpdateTime);
  cmd.Parse(argc, argv);
  // srand((unsigned)time(nullptr));
  srand(nSrandSeed);

  NodeContainer AdHocNodes;
  AdHocNodes.Create(nAdHocNum);
  for (uint32_t i = 0; i < nAdHocNum; ++i) {
    std::ostringstream os;
    os << "node-" << i;
    Names::Add(os.str(), AdHocNodes.Get(i));
    AdHocNodes.Get(i)->SetFlagValidTime(Seconds(kUpdateTime*10.));
    AdHocNodes.Get(i)->SetSuspiciousValidTime(Seconds(kUpdateTime*9.));
    AdHocNodes.Get(i)->SetAttackerValidTime(Seconds(kUpdateTime*8.));
    uint32_t tmp = (uint32_t)(kUpdateTime*8.*kMaxPacketsEverySeconds);
    AdHocNodes.Get(i)->SetAttackerThrsh(tmp);
    AdHocNodes.Get(i)->SetAttackerProb(1./tmp);
  }

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  phy.SetChannel(channel.Create());

  WifiHelper wifi;
  // wifi.SetStandard(WIFI_PHY_STANDARD_80211a); //设置标准
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
                               StringValue("OfdmRate6Mbps"));

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer AdHocDevices;
  AdHocDevices = wifi.Install(phy, mac, AdHocNodes);

  MobilityHelper mobility;
  RngSeedManager::SetSeed(nNs3Seed);
  // mobility.SetPositionAllocator(
  //     "ns3::GridPositionAllocator", "MinX", DoubleValue(0.0), "MinY",
  //     DoubleValue(0.0), "DeltaX", DoubleValue(nStep), "DeltaY", DoubleValue(0),
  //     "GridWidth", UintegerValue(nAdHocNum), "LayoutType",
  //     StringValue("RowFirst"));
  // mobility.SetPositionAllocator(
  //   "ns3::RandomDiscPositionAllocator", "X", StringValue("100.0"),
  //   "Y", StringValue("100.0"),
    // "Rho", StringValue("ns3::UniformRandomVariable[Min=0|Max=200]"));
  mobility.SetPositionAllocator(
    "ns3::RandomRectanglePositionAllocator",
    "X", StringValue("ns3::UniformRandomVariable[Min=0|Max=250]"),
    "Y", StringValue("ns3::UniformRandomVariable[Min=0|Max=250]")
  );
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(AdHocNodes);

  AodvHelper aodv;
  aodv.Set("HelloInterval", TimeValue (Seconds(2.)));
  Ipv4StaticRoutingHelper staticRouting;
  Ipv4ListRoutingHelper list;
  list.Add(staticRouting, 0);
  list.Add(aodv, 10);
  InternetStackHelper internet;
  internet.SetRoutingHelper(list);
  internet.Install(AdHocNodes);

  Ipv4AddressHelper address;
  address.SetBase("195.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer AdHocIp;
  AdHocIp = address.Assign(AdHocDevices);

  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowMonitorHelper;
  flowMonitor = flowMonitorHelper.Install(AdHocNodes);

  uint32_t normalport = 108;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for (uint32_t i = 0; i < AdHocNodes.GetN(); i++) {
    Ptr<Socket> recvProbeSocket = Socket::CreateSocket(AdHocNodes.Get(i), tid);
    recvProbeSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), kProbePort));
    recvProbeSocket->SetRecvCallback(MakeCallback(&recvProbeCallback));
    Simulator::Schedule(Seconds(1e-9), ThroughputMonitor, &flowMonitorHelper,
                        flowMonitor, recvProbeSocket,
                        std::map<FlowId, uint32_t>{});
    // Ptr<Socket> recvNormalSocket = Socket::CreateSocket(AdHocNodes.Get(i), tid);
    // recvNormalSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), normalport));
    // recvNormalSocket->SetRecvCallback(MakeCallback(&recvNormalCallback));
  }

  double totalTime = 30.0;
  double sendTime = 20.0;
  uint32_t recvid = 31;
  std::default_random_engine rng(nSrandSeed);
  std::uniform_real_distribution<double> uni(0.,2e-3);
  OnOffHelper onOffAttack("ns3::UdpSocketFactory", Address(InetSocketAddress(AdHocIp.GetAddress(recvid),normalport)));
  // SetConstantRate必须放前面
  onOffAttack.SetConstantRate(DataRate((kPacketSize<<3)*kAttackerRate), kPacketSize);
  onOffAttack.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onOffAttack.SetAttribute ("OffTime", StringValue ("ns3::UniformRandomVariable[Min=0|Max=0.02]"));
  
  // NodeContainer attackers;
  // attackers.Add(AdHocNodes.Get(4));
  // attackers.Add(AdHocNodes.Get(35));
  // ApplicationContainer appAttacker = onOffAttack.Install(attackers);
  ApplicationContainer appAttacker1 = onOffAttack.Install(AdHocNodes.Get(4));
  appAttacker1.Start(Seconds(1.5+uni(rng)));
  appAttacker1.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appAttacker2 = onOffAttack.Install(AdHocNodes.Get(35));
  appAttacker2.Start(Seconds(1.5+uni(rng)));
  appAttacker2.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appAttacker3 = onOffAttack.Install(AdHocNodes.Get(20));
  appAttacker3.Start(Seconds(1.5+uni(rng)));
  appAttacker3.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appAttacker4 = onOffAttack.Install(AdHocNodes.Get(0));
  appAttacker4.Start(Seconds(1.5+uni(rng)));
  appAttacker4.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appAttacker5 = onOffAttack.Install(AdHocNodes.Get(40));
  appAttacker5.Start(Seconds(1.5+uni(rng)));
  appAttacker5.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appAttacker6 = onOffAttack.Install(AdHocNodes.Get(24));
  appAttacker6.Start(Seconds(1.5+uni(rng)));
  appAttacker6.Stop(Seconds(1.5+sendTime));

  OnOffHelper onOffClient("ns3::UdpSocketFactory", Address(InetSocketAddress(AdHocIp.GetAddress(recvid),normalport)));
  // SetConstantRate必须放前面
  onOffClient.SetConstantRate(DataRate((kPacketSize<<3)*kClientRate), kPacketSize);
  onOffClient.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  onOffClient.SetAttribute ("OffTime", StringValue ("ns3::UniformRandomVariable[Min=0|Max=0.1]"));
  
  // NodeContainer clients;
  // clients.Add(AdHocNodes.Get(34));
  // clients.Add(AdHocNodes.Get(48));
  // ApplicationContainer appClient = onOffClient.Install(clients);
  ApplicationContainer appClient1 = onOffClient.Install(AdHocNodes.Get(34));
  appClient1.Start(Seconds(1.6+uni(rng)));
  appClient1.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appClient2 = onOffClient.Install(AdHocNodes.Get(48));
  appClient2.Start(Seconds(1.6+uni(rng)));
  appClient2.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appClient3 = onOffClient.Install(AdHocNodes.Get(33));
  appClient3.Start(Seconds(1.6+uni(rng)));
  appClient3.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appClient4 = onOffClient.Install(AdHocNodes.Get(13));
  appClient4.Start(Seconds(1.6+uni(rng)));
  appClient4.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appClient5 = onOffClient.Install(AdHocNodes.Get(56));
  appClient5.Start(Seconds(1.6+uni(rng)));
  appClient5.Stop(Seconds(1.5+sendTime));
  ApplicationContainer appClient6 = onOffClient.Install(AdHocNodes.Get(10));
  appClient6.Start(Seconds(1.6+uni(rng)));
  appClient6.Stop(Seconds(1.5+sendTime));
 
  PacketSinkHelper sinkHelper ("ns3::UdpSocketFactory", Address(InetSocketAddress (Ipv4Address::GetAny(), normalport)));
  ApplicationContainer appRecv = sinkHelper.Install(AdHocNodes.Get(recvid));
  // 因为socket绑定上在运行后，故用Schedule
  // Simulator::Schedule(Seconds(1.0),ChangeRecvBuffSize, appRecv.Get(0), 1<<12);
 
  appRecv.Start(Seconds(0.0));
  appRecv.Stop(Seconds(totalTime));

  // phy.EnablePcap("rgg2", AdHocDevices);
  // Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("rgg2.routes", std::ios::out);
  // aodv.PrintRoutingTableAllEvery(Seconds(1), routingStream);

  Simulator::Stop(Seconds(totalTime));
  Simulator::Run();

  // std::stringstream flowmonfile;
  // time_t rawtime;
  // struct tm *info;
  // time(&rawtime);
  // info = localtime(&rawtime);
  // char buff[80]={0};
  // sprintf(buff, "%d_%d_%d_%d_%d_%d", info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
  //                                    info->tm_hour, info->tm_min, info->tm_sec);
  // flowmonfile << "./rgg2_" << kProbContinue << "_" << kProbNew << "_" << nOutFileId << ".flowmon";
  // flowMonitor->SerializeToXmlFile(flowmonfile.str(), false, false);

  {
    std::map<FlowId, FlowMonitor::FlowStats> flowStats =
        flowMonitor->GetFlowStats();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper.GetClassifier());
    std::stringstream flowmonfile_simple;
    flowmonfile_simple.clear();
    flowmonfile_simple << "./rgg2_" << kProbContinue << "_" << kProbNew << "_" << nOutFileId << ".out";
    std::ofstream outfile(flowmonfile_simple.str());
    std::map<Ipv4Address, string> MP;
    std::vector<uint32_t> V;
    V.push_back(4), V.push_back(35), V.push_back(20);
    V.push_back(0), V.push_back(40), V.push_back(24);
    V.push_back(34), V.push_back(48), V.push_back(33);
    V.push_back(13), V.push_back(56), V.push_back(10);
    uint32_t txNum = 0, rxNum = 0;
    for (auto item : flowStats) {
      // FiveTuple五元组是：(source-ip, destination-ip, protocol, source-port,
      // destination-port)
      auto tmp = classifier->FindFlow(item.first);
      if (tmp.destinationAddress == AdHocIp.GetAddress(recvid) &&
          tmp.destinationPort == normalport) {
        //
        std::stringstream ss;
        ss<< tmp.sourceAddress << " >>> " << tmp.destinationAddress << ": ";
        ss<< item.second.txPackets << "/" << item.second.rxPackets;
        MP[tmp.sourceAddress] = ss.str();
        if (item.second.txPackets < 200){
          txNum +=item.second.txPackets;
          rxNum +=item.second.rxPackets;
        }
      }
    }
    for(auto x:V)
      outfile << MP[AdHocIp.GetAddress(x)] << std::endl;
    outfile << "total receive/send: " << 100.*rxNum/txNum << "%" << std::endl;
    outfile.close();
  }
  Simulator::Destroy();

  return 0;
}

static void recvNormalCallback(Ptr<Socket> sock) {
  NS_LOG_DEBUG(Now().GetSeconds() << "s, Normal Callback");
  Address org_src;
  Ptr<Packet> packet = sock->RecvFrom(org_src);
  InetSocketAddress inet_src = InetSocketAddress::ConvertFrom(org_src);

  NS_LOG_DEBUG("node name: " << Names::FindName(sock->GetNode()));
  NS_LOG_DEBUG("received a normal packet from " << inet_src.GetIpv4() << " "
                                                << inet_src.GetPort());
}

static void recvProbeCallback(Ptr<Socket> sock) {
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
  if(node->IsReceivedPid(org_tag.GetPid()))
    return;
  node->AddReceivedPid(org_tag.GetPid());

  Ptr<Ipv4L3Protocol> ipl3p = node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
  Ptr<aodv::RoutingProtocol> aodv_rtp =
      AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
  aodv::RoutingTable aodv_rtt = aodv_rtp->GetRoutingTable();
  std::default_random_engine rng(rand());
  std::uniform_real_distribution<double> uni(0.,2e-3);
  if (org_tag.GetFlag() != Node::kNodeFlag::FLAG_NORMAL) {
    // if (node->GetFlag() == Node::kNodeFlag::FLAG_NORMAL) {
    if (1) {
      auto mp = aodv_rtt.GetMap();
      set<Ipv4Address> tmp;
      for (auto item : mp) {
        aodv::RoutingTableEntry rtte = item.second;
        // Ipv4Address dst = item.first;
        // NS_LOG_DEBUG("dst: " << dst << ", rtte next hop: " << rtte.GetNextHop());
        Ipv4Address nexthop = rtte.GetNextHop();
        if (nexthop.IsLocalhost() || nexthop.IsBroadcast() ||
            nexthop.IsSubnetDirectedBroadcast(Ipv4Mask("255.255.255.0")) ||
            nexthop == inet_src.GetIpv4())
          continue;

        // send probe packet to neighbor
        // || (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE && org_tag.GetFlagTtl() == kProbeTtl + 1)
        if ((1.0 * rand() / RAND_MAX < kProbContinue &&
            org_tag.GetFlagTtl() > 1)) {
          if (tmp.find(nexthop) != tmp.end()) continue;
          tmp.insert(nexthop);
          NS_LOG_DEBUG(Now() << " send Origin packet to " << nexthop);
          Simulator::Schedule(Seconds(uni(rng)),
                              sendSpecialPacket, sock,
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
          Simulator::Schedule(
              Seconds(uni(rng)),
              sendSpecialPacket, sock, InetSocketAddress(nexthop, kProbePort),
              Node::kNodeFlag::FLAG_DEFEND, kDefendTtl, org_tag.GetPid(),
              org_tag.GetFilterPairs());
        }
      }
      tmp.clear();
    }
    // 检测节点
    if (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE && org_tag.GetFlagTtl() == kProbeTtl + 1)
      return;
    if (node->GetFlag() == Node::kNodeFlag::FLAG_PROBE && org_tag.GetFlag() == Node::kNodeFlag::FLAG_DEFEND)
      node->SetFlag(Node::kNodeFlag::FLAG_PROBE);  // 关键结点，延长时间
    else
      node->SetFlag(org_tag.GetFlag());
    for (auto item:org_tag.GetFilterPairs())
      node->AddSuspect(item);
  } else {
    // normal packet
    NS_LOG_DEBUG("???");
  }
}

void sendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl,uint32_t pid, std::set<filterPair> filterpairs) {
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

void sendNormalPacket(Ptr<Socket> sock,InetSocketAddress dst, uint32_t numPackets, Time interval){
  if(numPackets <= 0) return;
  Ptr<Packet> p = Create<Packet>(5);
  sock->SendTo(p, 0, dst);
  Simulator::Schedule(interval, &sendNormalPacket, sock, dst, numPackets - 1, interval);
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
      if(delta) S.insert(tmp.sourceAddress);
      rxMP[item.first] = item.second.rxPackets;
    }
  }
  if (num > (uint32_t)(kUpdateTime * kMaxPacketsEverySeconds)) {
    std::set<filterPair> S1;
    for(auto item:S){
      NS_LOG_DEBUG("suspicious path: " << item << " >> " << nodeip);
      S1.insert(std::make_pair(item, nodeip));
    } 
    Simulator::ScheduleNow(sendSpecialPacket, sock,
                            InetSocketAddress(nodeip, kProbePort),
                            Node::kNodeFlag::FLAG_PROBE, kProbeTtl + 1,
                            rand(), S1);// 因为向自己发包故+1
  }
  Simulator::Schedule(Seconds(kUpdateTime), &ThroughputMonitor,
                      flowMonitorHelper, flowMonitor, sock, rxMP);
}

void ChangeRecvBuffSize(Ptr<Application> app, uint32_t siz){
  Ptr<PacketSink> sink = app->GetObject<PacketSink>();
  assert(sink->GetListeningSocket()!=nullptr);
  // UintegerValue tmp;
  // sink->GetListeningSocket()->GetAttribute("RcvBufSize",tmp); cout<<tmp.Get()<<endl;
  sink->GetListeningSocket()->SetAttribute("RcvBufSize", UintegerValue(siz));
  // sink->GetListeningSocket()->GetAttribute("RcvBufSize",tmp); cout<<tmp.Get()<<endl;
  for (auto item:sink->GetAcceptedSockets())
    item->SetAttribute("RcvBufSize", UintegerValue(siz));
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
  return sizeof(uint32_t) * 2 + sizeof(uint32_t) * (2 * m_filterpairs.size() + 1);
}
void MyTag::Serialize(TagBuffer buffer) const {
  buffer.WriteU32(m_flag);
  buffer.WriteU32(m_ttl);
  uint32_t num = m_filterpairs.size();
  buffer.WriteU32(num);
  uint32_t ip;
  for(auto item:m_filterpairs){
    ip = item.first.Get();
    for (int i = 3; i >= 0; i--){
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
  for(uint32_t k = 0; k < num; k++){
    ip = 0;
    filterPair tmp;
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
  for(auto item : m_filterpairs) os << item.first << " >>> " << item.second << std::endl;
}
void MyTag::SetFlag(uint32_t value) { m_flag = value; }
uint32_t MyTag::GetFlag(void) const { return m_flag; }
void MyTag::SetFlagTtl(uint32_t ttl) { m_ttl = ttl; }
uint32_t MyTag::GetFlagTtl(void) const { return m_ttl; }
void MyTag::SetPid(uint32_t pid) { m_pid = pid; }
uint32_t MyTag::GetPid(void) const { return m_pid; }
void MyTag::SetFilterPairs(std::set<filterPair> pirs) { m_filterpairs = pirs; }
std::set<filterPair> MyTag::GetFilterPairs(void) { return m_filterpairs; }
