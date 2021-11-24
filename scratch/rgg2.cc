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

double kProbProbeContinue = 50;  // %
double kProbDefendContinue = 50;
// Node::kNodeFlag::FLAG_NORMAL = 0;
// Node::kNodeFlag::FLAG_PROBE = 1;
// Node::kNodeFlag::FLAG_DEFEND = 2;
uint32_t kProbePort = 2333;
uint32_t kProbeTtl = 3;
uint32_t kDefendTtl = 3;
uint32_t kPacketSize = 1 << 6;
uint32_t kMaxPacketsEverySeconds = 50;  // 每秒至多发x个包
// 每1s更新一次
double kUpdateTime = 0.5;
uint32_t kAttackerRate = kMaxPacketsEverySeconds;
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
// 模拟服务器接受，每隔一段时间(1s)统一接受，利用套接字缓冲队列溢出模拟服务器处理能力
void RecvNormal(Ptr<Socket> sock);
// 收到特殊包并转发
void RecvSpecailCallback(Ptr<Socket> sock);
// 绑定在Aodv协议中对CallBack，用于同步(激活)防御包发送
void AodvSendDependPacket(Ptr<Node> node, filterPair src2dst);
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

  time_t now = time(0);
  char *dt = ctime(&now);
  string stime(dt);
  while (stime.find(" ") != -1) stime = stime.replace(stime.find(" "), 1, "_");

  // LogComponentEnable("MyCode", LOG_LEVEL_INFO);
  // LogComponentEnable ("TcpL4Protocol", LOG_LEVEL_INFO);
  // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  // LogComponentEnable("AodvRoutingTable", LOG_LEVEL_ALL);
  // LogComponentEnable("UdpSocketImpl", LOG_LEVEL_ALL);
  // LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("Node", LOG_LEVEL_INFO);
  // LogComponentEnable("PacketSink", LOG_LEVEL_ALL);
  // LogComponentEnable("DefaultSimulatorImpl", LOG_LEVEL_ALL);

  uint32_t nAdHocNum = 60;
  uint32_t nNs3Seed = 6;
  uint32_t nSrandSeed = (unsigned)time(nullptr);
  uint32_t nOutFileId = 0;

  CommandLine cmd;
  cmd.AddValue("nAdHocNum", "Number of wifi ad devices", nAdHocNum);
  cmd.AddValue("nNs3Seed", "ns3 random seed", nNs3Seed);
  cmd.AddValue("nSrandSeed", "c++ random seed", nSrandSeed);
  cmd.AddValue("nOutFileId", "nOutFileId", nOutFileId);
  cmd.AddValue("kProbProbeContinue", "kProbProbeContinue p%",
               kProbProbeContinue);
  cmd.AddValue("kProbDefendContinue", "kProbDefendContinue p%",
               kProbDefendContinue);
  cmd.AddValue("kProbeTtl", "kProbeTtl", kProbeTtl);
  cmd.AddValue("kDefendTtl", "kDefendTtl", kDefendTtl);
  cmd.AddValue("kPacketSize", "kPacketSize", kPacketSize);
  cmd.AddValue("kPacketMaxSpeed", "kPacketMaxSpeed", kMaxPacketsEverySeconds);
  cmd.AddValue("kUpdateTime", "kUpdateTime", kUpdateTime);
  cmd.Parse(argc, argv);
  kProbProbeContinue /= 100.;
  kProbDefendContinue /= 100.;
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
    adhoc_nodes.Get(i)->SetDefendAttackerThrsh(2);
    adhoc_nodes.Get(i)->SetProbeAttackerThrsh(kClientRate *
                                              (uint32_t)(kUpdateTime * 10));
    adhoc_nodes.Get(i)->SetAttackerProb(0.5);
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
      StringValue("ns3::UniformRandomVariable[Min=0|Max=330]"), "Y",
      StringValue("ns3::UniformRandomVariable[Min=0|Max=330]"));
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  // mobility.SetMobilityModel(
  //     "ns3::RandomWalk2dMobilityModel", "Mode", StringValue("Time"), "Time",
  //     StringValue("2s"), "Speed",
  //     StringValue("ns3::UniformRandomVariable[Min=2.5|Max=5.0]"), "Bounds",
  //     RectangleValue(Rectangle(0.0, 250.0, 0.0, 250.0)));
  mobility.Install(adhoc_nodes);

  AodvHelper aodv;
  // aodv.Set("HelloInterval", TimeValue(Seconds(2.)));
  Ipv4StaticRoutingHelper static_routing;
  Ipv4ListRoutingHelper list;
  list.Add(static_routing, 0);
  list.Add(aodv, 10);
  InternetStackHelper internet;
  internet.SetRoutingHelper(list);
  internet.Install(adhoc_nodes);

  // 在aodv协议中绑定防御包发送
  for (uint32_t i = 0; i < nAdHocNum; ++i) {
    Ptr<Ipv4L3Protocol> ipl3p = adhoc_nodes.Get(i)->GetObject<Ipv4L3Protocol>();
    Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
    Ptr<aodv::RoutingProtocol> aodv_rtp =
        AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
    aodv_rtp->SetDefendCallback(MakeCallback(&AodvSendDependPacket));
  }

  Ipv4AddressHelper address;
  address.SetBase("195.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer adhoc_ipv4;
  adhoc_ipv4 = address.Assign(adhoc_devices);

  // 流量监控
  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowMonitorHelper;
  flowMonitor = flowMonitorHelper.Install(adhoc_nodes);

  uint32_t normalport = 108;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for (uint32_t i = 0; i < adhoc_nodes.GetN(); i++) {
    Ptr<Socket> recvProbeSocket = Socket::CreateSocket(adhoc_nodes.Get(i), tid);
    recvProbeSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), kProbePort));
    recvProbeSocket->SetRecvCallback(MakeCallback(&RecvSpecailCallback));
    // 安排间隔流量监控，激活探测包发送
    Simulator::Schedule(Seconds(1e-9), ThroughputMonitor, &flowMonitorHelper,
                        flowMonitor, recvProbeSocket,
                        std::map<FlowId, uint32_t>{});
  }

  double send_time = 20;
  double total_time = send_time + 10;
  uint32_t recvid = 6;
  std::default_random_engine rng(nSrandSeed);
  std::uniform_real_distribution<double> uni(1e-6, 2e-3);
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
    vector<uint32_t> V{4, 35, 20, 0, 40, 24};
    shuffle(V.begin(), V.end(), rng);
    for (auto x : V) attackers.Add(adhoc_nodes.Get(x));
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
    vector<uint32_t> V{34, 48, 33, 13, 56, 10, 1,  22, 44,
                       5,  31,  7,  15, 16, 17, 51, 52, 53};
    shuffle(V.begin(), V.end(), rng);
    for (auto x : V) {
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

  // 设置服务器接受套接字，并设置Buffer大小
  Ptr<Socket> recvsocket = Socket::CreateSocket(adhoc_nodes.Get(recvid), tid);
  recvsocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), normalport));
  recvsocket->SetAttribute(
      "RcvBufSize", UintegerValue(kPacketSize * kMaxPacketsEverySeconds));
  // 间隔接受Buffer中数据，以Buffer满模拟服务器处理达到上界以此模拟服务器处理能力
  Simulator::Schedule(Seconds(1e-9), &RecvNormal, recvsocket);

  // phy.EnablePcap("rgg2", adhoc_devices);
  // Ptr<OutputStreamWrapper> routingStream =
  // Create<OutputStreamWrapper>("rgg2.routes", std::ios::out);
  // aodv.PrintRoutingTableAllEvery(Seconds(1), routingStream);

  Simulator::Stop(Seconds(total_time));
  Simulator::Run();

  std::stringstream flowmonfile;
  flowmonfile.precision(2);
  flowmonfile << "./rgg2data/smallpacket_" << std::setiosflags(ios::fixed)
              << kProbProbeContinue << "_" << std::setiosflags(ios::fixed)
              << kProbDefendContinue << "_" << nOutFileId << ".flowmon";
  // flowMonitor->SerializeToXmlFile(flowmonfile.str(), false, false);

  {
    std::map<FlowId, FlowMonitor::FlowStats> flowStats =
        flowMonitor->GetFlowStats();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper.GetClassifier());
    std::stringstream flowmonfile_simple;
    flowmonfile_simple.precision(2);

    // flowmonfile_simple << "./rgg2data/11-24/20s_"
    //                    << std::setiosflags(ios::fixed) << kProbProbeContinue
    //                    << "_" << std::setiosflags(ios::fixed)
    //                    << kProbDefendContinue << "_" << nOutFileId << ".out";
    flowmonfile_simple << "./rgg2data/11-24/" << stime;
    std::ofstream outfile(flowmonfile_simple.str());
    std::map<Ipv4Address, string> MP;
    std::vector<uint32_t> V;
    V.push_back(4), V.push_back(35), V.push_back(20);
    V.push_back(0), V.push_back(40), V.push_back(24);
    V.push_back(34), V.push_back(48), V.push_back(33);
    V.push_back(13), V.push_back(56), V.push_back(10);
    V.push_back(1), V.push_back(22), V.push_back(44);
    V.push_back(5), V.push_back(31), V.push_back(7);
    V.push_back(15), V.push_back(16), V.push_back(17);
    V.push_back(51), V.push_back(52), V.push_back(53);
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
    outfile << "Number of wifi ad devices " << nAdHocNum << std::endl;
    outfile << "ns3 random seed " << nNs3Seed << std::endl;
    outfile << "c++ random seed " << nSrandSeed << std::endl;
    outfile << "nOutFileId " << nOutFileId << std::endl;
    outfile << "kProbProbeContinue p% " << kProbProbeContinue << std::endl;
    outfile << "kProbDefendContinue p% " << kProbDefendContinue << std::endl;
    outfile << "kProbeTtl " << kProbeTtl << std::endl;
    outfile << "kDefendTtl " << kDefendTtl << std::endl;
    outfile << "kPacketSize " << kPacketSize << std::endl;
    outfile << "kPacketMaxSpeed " << kMaxPacketsEverySeconds << std::endl;
    outfile << "kUpdateTime " << kUpdateTime << std::endl;
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
  NS_LOG_DEBUG(Now().GetSeconds() << ", Normal");
  std::cout << Now().GetSeconds() << ", Normal" << std::endl;
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

void RecvSpecailCallback(Ptr<Socket> sock) {
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
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  Ipv4Address nodeip = ipv4->GetAddress(1, 0).GetLocal();

  Ptr<Ipv4L3Protocol> ipl3p = node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
  Ptr<aodv::RoutingProtocol> aodv_rtp =
      AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
  aodv::RoutingTable aodv_rtt = aodv_rtp->GetRoutingTable();
  std::default_random_engine rng(rand());
  std::uniform_real_distribution<double> uni(1e-6, 2e-3);
  if (org_tag.GetFlag() != Node::kNodeFlag::FLAG_NORMAL) {
    if (node->GetFlag() == Node::kNodeFlag::FLAG_NORMAL)
      node->SetFlag(org_tag.GetFlag());
    for (auto item : org_tag.GetFilterPairs()) {
      node->AddSuspect(item);
      if (node->GetFlag() == Node::kNodeFlag::FLAG_DEFEND) {
        node->AddAttacker(item);
        if (node->IsAttacker(item)) {
          std::cout << "=======!!!!!!!=======" << std::endl;
          std::cout << Names::FindName(node) << ": " << item.first << ">>>"
                    << item.second << std::endl;
        }
      }
    }

    if (org_tag.GetFlagTtl() >= 1) {
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
        double rnd = 1. * rand() / RAND_MAX;
        if (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
            rnd > kProbProbeContinue)
          continue;
        if (org_tag.GetFlag() == Node::kNodeFlag::FLAG_DEFEND &&
            rnd > kProbDefendContinue)
          continue;
        if (tmp.find(nexthop) != tmp.end()) continue;
        tmp.insert(nexthop);
        NS_LOG_DEBUG(Now() << " forward packet to " << nexthop);
        SendSpecialPacket(sock, InetSocketAddress(nexthop, kProbePort),
                          org_tag.GetFlag(), org_tag.GetFlagTtl() - 1,
                          org_tag.GetPid(), org_tag.GetFilterPairs());
      }
      tmp.clear();
    }
  } else {
    // normal packet
    NS_LOG_DEBUG("???");
  }
}

void AodvSendDependPacket(Ptr<Node> node, filterPair src2dst) {
  Ptr<Socket> sock =
      Socket::CreateSocket(node, TypeId::LookupByName("ns3::UdpSocketFactory"));
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  Ipv4Address nodeip = ipv4->GetAddress(1, 0).GetLocal();
  std::set<filterPair> S{src2dst};
  SendSpecialPacket(sock, InetSocketAddress(nodeip, kProbePort),
                    Node::kNodeFlag::FLAG_DEFEND, kDefendTtl, rand(), S);
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
        tmp.destinationPort != aodv::RoutingProtocol::AODV_PORT &&
        tmp.sourceAddress != nodeip) {
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
      std::cout << Now() << ", "
                << "suspicious path: " << item << " >> " << nodeip << std::endl;
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
