#include <bits/stdc++.h>
#include "ns3/aodv-helper.h"
#include "ns3/aodv-routing-protocol.h"
#include "ns3/aodv-rtable.h"
#include "ns3/dsdv-helper.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/energy-module.h"
#include "ns3/energy-source-container.h"
#include "ns3/wifi-radio-energy-model-helper.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("MyCode");

/// RGB structure
struct rgb {
  uint8_t r;  ///< red
  uint8_t g;  ///< green
  uint8_t b;  ///< blue
};
struct rgb kColors[] = {
    {0xff, 0, 0},     // Red-default
    {0, 0, 0xff},     // Blue-probe
    {0xff, 0xff, 0},  // Yellow-defend
    {0xff, 0, 0xff},  // Purple-server
    {0, 0xff, 0},     // Green-client
    {0, 0xff, 0xff},        // client-probe
    {0x6e, 0x97, 0x49},        // client-defend
    {0, 0, 0},        // Black-attacker
};

double kProbProbeContinue = 50;  // %
double kProbDefendContinue = 50;
// Node::kNodeFlag::FLAG_NORMAL = 0;
// Node::kNodeFlag::FLAG_PROBE = 1;
// Node::kNodeFlag::FLAG_DEFEND = 2;
uint32_t kProbePort = 2333;
uint32_t kProbeTtl = 3;
uint32_t kDefendTtl = 3;
uint32_t kPacketSize = 1 << 6;
uint32_t kServerRate = 50;  // 每秒至收发x个包
// 每xs更新一次
double kUpdateTime = 0.5;
uint32_t kAttackerRate = kServerRate;
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
  void SetSendnid(uint32_t nid);
  uint32_t GetSendnid(void) const;
  void SetPid(uint32_t pid);
  uint32_t GetPid(void) const;
  void SetFilterPairs(std::set<filterPair> filterpairs);
  std::set<filterPair> GetFilterPairs(void);

 private:
  uint32_t m_flag;
  uint32_t m_ttl;
  uint32_t m_sendnid;  //信息源结点ids
  uint32_t m_pid;      //包id
  std::set<filterPair> m_filterpairs;
};
std::ostream &operator<<(std::ostream &os, MyTag const &mytag) {
  mytag.Print(os);
  return os;
}

AnimationInterface *pAnim = 0;
std::set<Ipv4Address> Sclientip;
std::map<Ipv4Address, uint32_t> MPclientcnt;
uint32_t cnt_recvnormalpacket;
// 模拟服务器接受，每隔一段时间(1s)统一接受，利用套接字缓冲队列溢出模拟服务器处理能力
void RecvNormal(Ptr<Socket> sock, double interval);
// 收到特殊包并转发
void RecvSpecailCallback(Ptr<Socket> sock);
// 绑定在Aodv协议中对CallBack，用于同步(激活)防御包发送
void AodvSendDefendPacket(Ptr<Node> node, filterPair src2dst);
void SendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl, uint32_t nid, uint32_t pid,
                       std::set<filterPair> filterpairs);
// 对特定ip进行流量监测
void ThroughputMonitor(FlowMonitorHelper *flowMonitorHelper,
                       Ptr<FlowMonitor> flowMonitor, Ptr<Socket> sock,
                       std::map<FlowId, uint32_t> &rxMP);
std::map<uint32_t, uint32_t> MPid2colortype;
// 更新节点颜色(主要考虑特殊节点变回普通节点)
void UpdateNodeColor(NodeContainer nodes,
                     std::map<uint32_t, uint32_t> MPid2colortype,
                     double interval);
void OutputVal(std::ofstream);

int main(int argc, char *argv[]) {
  Time::SetResolution(Time::NS);
  // LogComponentEnable("MyCode", LOG_LEVEL_ALL);
  // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  // LogComponentEnable("OnOffApplication", LOG_LEVEL_ALL);
  // LogComponentEnable("AodvRequestQueue", LOG_LEVEL_ALL);
  // NS_LOG_DEBUG("Test LOG");

  time_t now = time(0);
  char *dt = ctime(&now);
  string stime(dt);
  while (stime.find(" ") != -1) stime = stime.replace(stime.find(" "), 1, "_");
  while (stime.find(":") != -1) stime = stime.replace(stime.find(":"), 1, "_");
  stime.pop_back();

  uint32_t nAdHocNum = 60;
  uint32_t nNs3Seed = 6;
  uint32_t nSrandSeed = (unsigned)time(nullptr);
  uint32_t nOutFileId = 0;
  double send_start_time = 30;
  double send_end_time = 90;
  double total_time = send_end_time + 5;
  // Config::SetDefault("ns3::WifiMacQueue::MaxSize", QueueSizeValue(QueueSize(QueueSizeUnit::PACKETS, std::numeric_limits<int32_t>::max())));
  // Config::SetDefault("ns3::WifiMacQueue::MaxDelay", TimeValue(Seconds(10)));
  Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue("DsssRate11Mbps"));

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
  cmd.AddValue("kServerRate", "kServerRate", kServerRate);
  cmd.AddValue("kAttackerRate", "kAttackerRate", kAttackerRate);
  cmd.AddValue("kUpdateTime", "kUpdateTime", kUpdateTime);
  cmd.Parse(argc, argv);
  kProbProbeContinue /= 1000.;
  kProbDefendContinue /= 100.;
  // srand((unsigned)time(nullptr));
  srand(nSrandSeed);

  NodeContainer adhoc_nodes;
  adhoc_nodes.Create(nAdHocNum);
  for (uint32_t i = 0; i < nAdHocNum; ++i) {
    std::ostringstream os;
    os << "node-" << i;
    Names::Add(os.str(), adhoc_nodes.Get(i));
    adhoc_nodes.Get(i)->SetFlagValidTime(Seconds(kUpdateTime * 60.));
    adhoc_nodes.Get(i)->SetSuspiciousValidTime(Seconds(kUpdateTime * 59.));
    adhoc_nodes.Get(i)->SetAttackerValidTime(Seconds(kUpdateTime * 58.));
    adhoc_nodes.Get(i)->SetProbeResendThrsh(10);
    adhoc_nodes.Get(i)->SetDefendAttackerThrsh(2);
    adhoc_nodes.Get(i)->SetProbeAttackerThrsh(kClientRate *
                                              (uint32_t)(kUpdateTime * 60));
    adhoc_nodes.Get(i)->SetAttackerProb(0.5);
  }

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  // wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel");
  wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange", DoubleValue (250));
  YansWifiPhyHelper wifiPhy;
  // wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
  // wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));
  // wifiPhy.SetPcapDataLinkType(YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
  wifiPhy.SetChannel(wifiChannel.Create());

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211b); //设置标准
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                "DataMode", StringValue("DsssRate11Mbps"),
                                "ControlMode", StringValue("DsssRate11Mbps"),
                                "RtsCtsThreshold", UintegerValue(2000));

  WifiMacHelper wifiMac;
  wifiMac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer adhoc_devices;
  adhoc_devices = wifi.Install(wifiPhy, wifiMac, adhoc_nodes);

  uint32_t serverid = 0;

  RngSeedManager::SetSeed(nNs3Seed);
  MobilityHelper mobility;
  double xMax = 1000, yMax = 2000;
  {
    Ptr<ListPositionAllocator> positionAP = CreateObject<ListPositionAllocator>();
    positionAP->Add(Vector(xMax / 2, yMax / 2, 0));
    mobility.SetPositionAllocator(positionAP);
    mobility.Install(adhoc_nodes.Get(serverid));
  }
  {
    Ptr<ListPositionAllocator> positionAP = CreateObject<ListPositionAllocator>();
    positionAP->Add(Vector(0.1*xMax, 0.1*yMax, 0));
    mobility.SetPositionAllocator(positionAP);
    mobility.Install(adhoc_nodes.Get(1));
  }
  {
    Ptr<ListPositionAllocator> positionAP = CreateObject<ListPositionAllocator>();
    positionAP->Add(Vector(0.9*xMax, 0.1*yMax, 0));
    mobility.SetPositionAllocator(positionAP);
    mobility.Install(adhoc_nodes.Get(2));
  }
  {
    Ptr<ListPositionAllocator> positionAP = CreateObject<ListPositionAllocator>();
    positionAP->Add(Vector(0.9*xMax, 0.9*yMax, 0));
    mobility.SetPositionAllocator(positionAP);
    mobility.Install(adhoc_nodes.Get(3));
  }
  {
    Ptr<ListPositionAllocator> positionAP = CreateObject<ListPositionAllocator>();
    positionAP->Add(Vector(0.1*xMax, 0.9*yMax, 0));
    mobility.SetPositionAllocator(positionAP);
    mobility.Install(adhoc_nodes.Get(4));
  }

  Ptr<RandomRectanglePositionAllocator> randomPosition =
    CreateObject<RandomRectanglePositionAllocator>();
  randomPosition->SetAttribute(
      "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
  randomPosition->SetAttribute(
      "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=2000.0]"));
  mobility.SetPositionAllocator(randomPosition);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  // mobility.SetMobilityModel(
  //     "ns3::RandomWalk2dMobilityModel", "Mode", StringValue("Time"),
  //     "Time", StringValue("2s"),
  //     "Speed", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=50.0]"),
  //     "Bounds", RectangleValue(Rectangle(0.0, 1000.0, 0.0, 2000.0)));
  // mobility.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
  //                               "Speed", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=20.0]"),
  //                               "Pause", StringValue ("ns3::ConstantRandomVariable[Constant=0]"),
  //                               "PositionAllocator", PointerValue (randomPosition));
  for (uint32_t i = 1 + 4; i < adhoc_nodes.GetN(); i++) 
      mobility.Install(adhoc_nodes.Get(i));

  AodvHelper aodv;
  // aodv.Set("HelloInterval", TimeValue(Seconds(999.)));
  aodv.Set("MaxQueueLen", UintegerValue(std::numeric_limits<int32_t>::max()));
  // aodv.Set("ActiveRouteTimeout", TimeValue(Seconds(0.5)));
  // aodv.Set("DeletePeriod", TimeValue(Seconds(1)));
  Ipv4StaticRoutingHelper static_routing; // 给自身发包
  Ipv4ListRoutingHelper list;
  list.Add(static_routing, 0);
  list.Add(aodv, 10);
  InternetStackHelper internet;
  internet.SetRoutingHelper(list);
  internet.Install(adhoc_nodes);

  /** Energy Model **/
  BasicEnergySourceHelper basicSourceHelper;
  basicSourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(50000.0));// configure energy source for StaNodes
  EnergySourceContainer sources = basicSourceHelper.Install(adhoc_nodes);
  WifiRadioEnergyModelHelper radioEnergyHelper;
  radioEnergyHelper.Set ("IdleCurrentA", DoubleValue (0.1));
  DeviceEnergyModelContainer adhoc_device_energy_model = radioEnergyHelper.Install(adhoc_devices, sources); // install device model

  // 在aodv协议中绑定防御包发送
  for (uint32_t i = 0; i < nAdHocNum; i++) {
    Ptr<Ipv4L3Protocol> ipl3p = adhoc_nodes.Get(i)->GetObject<Ipv4L3Protocol>();
    Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
    Ptr<aodv::RoutingProtocol> aodv_rtp =
        AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
    aodv_rtp->SetDefendCallback(MakeCallback(&AodvSendDefendPacket));
  }

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer adhoc_ipv4;
  adhoc_ipv4 = address.Assign(adhoc_devices);

  pAnim = new AnimationInterface("test.xml");
  pAnim->SetStartTime(Seconds(1));
  // pAnim->SetStopTime(Seconds(1.1));
  pAnim->SetMaxPktsPerTraceFile(100000);
  pAnim->EnablePacketMetadata();
  pAnim->EnableIpv4RouteTracking("rgg2.routes", Seconds(0), Seconds(send_end_time));

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
    Simulator::Schedule(Seconds(1e-9), &ThroughputMonitor, &flowMonitorHelper,
                        flowMonitor, recvProbeSocket,
                        std::map<FlowId, uint32_t>{});
    MPid2colortype[i] = 0;  // default color
  }

  // uint32_t serverid = 6;

  NodeContainer attackers;
  {
    std::default_random_engine rng(nSrandSeed);
    std::uniform_real_distribution<double> uni(1e-6, 2.);
    // vector<uint32_t> V{64, 35, 83, 0, 62, 24};
    vector<uint32_t> V{1, 2, 3, 4};
    shuffle(V.begin(), V.end(), rng);
    for (auto x : V) {
      OnOffHelper onOffAttack(
          "ns3::UdpSocketFactory",
          Address(InetSocketAddress(adhoc_ipv4.GetAddress(serverid), normalport)));
      // SetConstantRate必须放前面
      onOffAttack.SetConstantRate(DataRate((kPacketSize << 3) * kAttackerRate),
                                  kPacketSize);
      onOffAttack.SetAttribute(
          "OnTime", StringValue("ns3::ConstantRandomVariable[Constant=2]"));
      onOffAttack.SetAttribute(
          "OffTime", StringValue("ns3::UniformRandomVariable[Min=0|Max=0.1]"));
      attackers.Add(adhoc_nodes.Get(x));
      // pAnim->UpdateNodeDescription(adhoc_nodes.Get(x), "attacker");
      // pAnim->UpdateNodeColor(adhoc_nodes.Get(x), kColors[7].r, kColors[7].g, kColors[7].b);
      MPid2colortype[x] = 7;
      ApplicationContainer appAttacker = onOffAttack.Install(adhoc_nodes.Get(x));
      appAttacker.Start(Seconds(send_start_time + uni(rng)));
      appAttacker.Stop(Seconds(send_end_time));
    }
  }


  NodeContainer clients;
  {
    std::default_random_engine rng(nSrandSeed);
    std::uniform_real_distribution<double> uni(1e-6, 2.);
    vector<uint32_t> V{5,6,7,8,9,10,11,12,13,14};
    // vector<uint32_t> V{34, 48, 33, 13, 56, 10, 1,  22, 44,
    //                    5,  31,  7,  15, 16, 17, 51, 52, 53};
    // vector<uint32_t> V{26, 4, 3, 19, 1};
    shuffle(V.begin(), V.end(), rng);
    for (auto x : V) {
      OnOffHelper onOffClient(
          "ns3::UdpSocketFactory",
          Address(InetSocketAddress(adhoc_ipv4.GetAddress(serverid), normalport)));
      // SetConstantRate必须放前面
      onOffClient.SetConstantRate(DataRate((kPacketSize << 3) * kClientRate),
                                  kPacketSize);
      onOffClient.SetAttribute(
          "OnTime", StringValue("ns3::ConstantRandomVariable[Constant=2]"));
      onOffClient.SetAttribute(
          "OffTime", StringValue("ns3::UniformRandomVariable[Min=2|Max=4]"));
      clients.Add(adhoc_nodes.Get(x));
      // pAnim->UpdateNodeDescription(adhoc_nodes.Get(x), "client");
      // pAnim->UpdateNodeColor(adhoc_nodes.Get(x), kColors[4].r, kColors[4].g, kColors[4].b);
      MPid2colortype[x] = 4;
      Sclientip.insert(adhoc_ipv4.GetAddress(x));
      ApplicationContainer appClient = onOffClient.Install(adhoc_nodes.Get(x));
      appClient.Start(Seconds(send_start_time + uni(rng)));
      appClient.Stop(Seconds(send_end_time));
    }
  }

  // pAnim->UpdateNodeDescription(adhoc_nodes.Get(serverid), "server");
  // pAnim->UpdateNodeColor(adhoc_nodes.Get(serverid), kColors[3].r, kColors[3].g, kColors[3].b);
  MPid2colortype[serverid] = 3;
  // 设置服务器接受套接字，并设置Buffer大小
  {
    Ptr<Socket> recvsocket = Socket::CreateSocket(adhoc_nodes.Get(serverid), TypeId::LookupByName("ns3::UdpSocketFactory"));
    recvsocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), normalport));
    double recv_interval = 0.5;
    recvsocket->SetAttribute("RcvBufSize", UintegerValue(kPacketSize * kServerRate * recv_interval));
    // 间隔接受Buffer中数据，以Buffer满模拟服务器处理达到上界以此模拟服务器处理能力
    Simulator::Schedule(Seconds(1e-9), &RecvNormal, recvsocket, recv_interval);
  }

  // 设置颜色变化更新
  // Simulator::Schedule(Seconds(1e-3), &UpdateNodeColor, adhoc_nodes, MPid2colortype, kUpdateTime);

  // phy.EnablePcapAll("./rgg2data/pcap/rgg2", true);
  // Ptr<OutputStreamWrapper> routingStream =
  // Create<OutputStreamWrapper>("rgg2.routes", std::ios::out);
  // aodv.PrintRoutingTableAllEvery(Seconds(1), routingStream);

  Simulator::Stop(Seconds(total_time));

  std::cout << "Start" << std::endl;
  Simulator::Run();
  {
    std::stringstream flowmonfile_simple;
    flowmonfile_simple.precision(3);
    // flowMonitor->SerializeToXmlFile("./rgg2_test.flowmon",true,true);

    // flowmonfile_simple << "./rgg2data/vary_p1_3_morenode/log_" << stime << ".out";
    flowmonfile_simple << "./rgg2data/vary_p1_energy/log_" << nOutFileId << "_p1_"
                       << std::setiosflags(ios::fixed) << kProbProbeContinue << ".out";
    // flowmonfile_simple << "./rgg2data/vary_p2_3_test/log_" << nOutFileId << "_p2_"
    //                    << std::setiosflags(ios::fixed) << kProbDefendContinue << ".out";
    // flowmonfile_simple << "./rgg2data/vary_p1_3_test/log_" << nOutFileId << "_noattack"<< ".out";
    std::ofstream outfile(flowmonfile_simple.str());
    std::map<FlowId, FlowMonitor::FlowStats> flowStats =
        flowMonitor->GetFlowStats();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowMonitorHelper.GetClassifier());
    std::map<Ipv4Address, string> MP;
    std::vector<uint32_t> V;
    for (uint32_t i = 0; i < attackers.GetN(); i++)
      V.push_back(attackers.Get(i)->GetId());
    for (uint32_t i = 0; i < clients.GetN(); i++)
      V.push_back(clients.Get(i)->GetId());
    uint32_t txcnt = 0, rxcnt = 0;
    Time avg_delay = Seconds(0), avg_jitter = Seconds(0);
    double avg_throughput = 0;
    for (auto item : flowStats) {
      // FiveTuple五元组是：(source-ip, destination-ip, protocol, source-port,
      // destination-port)
      auto tmp = classifier->FindFlow(item.first);
      if (tmp.destinationAddress == adhoc_ipv4.GetAddress(serverid) &&
          tmp.destinationPort == normalport) {
        //
        std::stringstream ss;
        ss << tmp.sourceAddress << " >>> " << tmp.destinationAddress;
        ss << ", IP layer: " << item.second.txPackets << "/" << item.second.rxPackets;
        if(Sclientip.find(tmp.sourceAddress) != Sclientip.end()){
          ss << ", Socket(Application): " << item.second.rxPackets << "/" << MPclientcnt[tmp.sourceAddress];
          txcnt += item.second.txPackets;
          rxcnt += item.second.rxPackets;
          avg_delay += item.second.delaySum;
          avg_jitter += item.second.jitterSum;
          avg_throughput += item.second.rxBytes * 8 / (item.second.timeLastRxPacket.GetSeconds() - 
                                                       item.second.timeFirstTxPacket.GetSeconds()) / 1000;
        }
        MP[tmp.sourceAddress] = ss.str();
      }
    }
    avg_delay = avg_delay / rxcnt;
    avg_jitter = avg_jitter / rxcnt;

    outfile << stime << std::endl;
    // outfile << "Mobility" << std::endl;
    outfile << "======Params======" << std::endl;
    outfile << "Number of wifi ad devices " << nAdHocNum << std::endl;
    outfile << "ns3 random seed " << nNs3Seed << std::endl;
    outfile << "c++ random seed " << nSrandSeed << std::endl;
    // outfile << "nOutFileId " << nOutFileId << std::endl;
    outfile << "p1:kProbProbeContinue " << kProbProbeContinue << std::endl;
    outfile << "p2:kProbDefendContinue " << kProbDefendContinue << std::endl;
    outfile << "kProbeTtl " << kProbeTtl << std::endl;
    outfile << "kDefendTtl " << kDefendTtl << std::endl;
    outfile << "kPacketSize(B) " << kPacketSize << std::endl;
    outfile << "kServerRate(packet/s) " << kServerRate
            << std::endl;
    outfile << "kAttackerRate(packet/s) " << kAttackerRate
            << std::endl;
    outfile << "kUpdateTime(s) " << kUpdateTime << std::endl;
    outfile << "FlagValidTime(s) " << adhoc_nodes.Get(0)->GetFlagValidTime() << std::endl;
    outfile << "SuspiciousValidTime(s) " << adhoc_nodes.Get(0)->GetSuspiciousValidTime() << std::endl;
    outfile << "AttackerValidTime(s) " << adhoc_nodes.Get(0)->GetAttackerValidTime() << std::endl;
    outfile << "ProbeAttackerThrsh(s) " << adhoc_nodes.Get(0)->GetProbeAttackerThrsh() << std::endl;
    outfile << "p3:AttackerProb(s) " << adhoc_nodes.Get(0)->GetAttackerProb() << std::endl;
    outfile << "DefendAttackerThrsh(s) " << adhoc_nodes.Get(0)->GetDefendAttackerThrsh() << std::endl;

    outfile << "======client======" << std::endl;
    for (auto x : V) outfile << MP[adhoc_ipv4.GetAddress(x)] << std::endl;

    outfile << "======total=======" << std::endl;
    outfile << "average delay: " << avg_delay << std::endl;
    outfile << "average jitter: " << avg_jitter << std::endl;
    outfile << "average throughput: " << avg_throughput << " Kbps" << std::endl;
    outfile << "Ip layer total receive/send: " << 100. * rxcnt / txcnt << "%"
            << std::endl;
    outfile << "Socket total accept/send: " << 100. * cnt_recvnormalpacket / txcnt << "%" << std::endl;
    outfile << "App total accept/receive: " << 100. * cnt_recvnormalpacket / rxcnt << "%" << std::endl;
    double tot_energy = 0;
    for(auto iter = adhoc_device_energy_model.Begin(); iter != adhoc_device_energy_model.End(); iter++) {
      double energyConsumed = (*iter)->GetTotalEnergyConsumption ();
      tot_energy += energyConsumed;
    }
    outfile << "Total Energy Consumption: " << tot_energy << "J" << std::endl;
    outfile.close();
  }


  Simulator::Destroy();
  delete pAnim;

  return 0;
}

void RecvNormal(Ptr<Socket> sock, double interval) {
  std::cout << Now().GetSeconds() << "s, Normal" << std::endl;
  Address org_src;
  Ptr<Packet> packet;
  while (packet = sock->RecvFrom(org_src)) {
    InetSocketAddress inet_src = InetSocketAddress::ConvertFrom(org_src);
    std::cout << "received a normal packet from " << inet_src.GetIpv4() << " "
              << inet_src.GetPort() << std::endl;
    if (Sclientip.find(inet_src.GetIpv4()) != Sclientip.end()){
      cnt_recvnormalpacket++;
      MPclientcnt[inet_src.GetIpv4()]++;
    }
  }
  Simulator::Schedule(Seconds(interval), &RecvNormal, sock, interval);
}

void RecvSpecailCallback(Ptr<Socket> sock) {
  NS_LOG_DEBUG("Probe Callback");

  Address org_src;
  Ptr<Packet> packet = sock->RecvFrom(org_src);
  InetSocketAddress inet_src = InetSocketAddress::ConvertFrom(org_src);

  MyTag probetag;
  packet->PeekPacketTag(probetag);

  NS_LOG_DEBUG("node name: " << Names::FindName(sock->GetNode()));
  NS_LOG_DEBUG("received a special packet from " << inet_src.GetIpv4() << " "
                                                 << inet_src.GetPort());
  NS_LOG_DEBUG(probetag);

  Ptr<Node> node = sock->GetNode();
  if (node->IsReceivedPid(probetag.GetPid())) return;
  node->AddReceivedPid(probetag.GetPid());
  // std::cout << Names::FindName(node) << " Pid: " << probetag.GetPid() <<
  // std::endl;

  if (MPid2colortype[node->GetId()] == 7) return; // attacker

  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  Ipv4Address nodeip = ipv4->GetAddress(1, 0).GetLocal();

  Ptr<Ipv4L3Protocol> ipl3p = node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
  Ptr<aodv::RoutingProtocol> aodv_rtp =
      AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
  aodv::RoutingTable aodv_rtt = aodv_rtp->GetRoutingTable();
  std::default_random_engine rng(rand());
  if (probetag.GetFlag() != Node::kNodeFlag::FLAG_NORMAL) {
    if (node->GetFlag() == Node::kNodeFlag::FLAG_NORMAL || probetag.GetFlag() == Node::kNodeFlag::FLAG_PROBE) {
      node->SetFlag(probetag.GetFlag());
      if (MPid2colortype[node->GetId()] == 0) {
        uint32_t cid = probetag.GetFlag();
        // pAnim->UpdateNodeColor(node, kColors[cid].r, kColors[cid].g, kColors[cid].b);
      }
      else if (MPid2colortype[node->GetId()] == 4) {
        uint32_t cid = probetag.GetFlag() + 4;
        // pAnim->UpdateNodeColor(node, kColors[cid].r, kColors[cid].g, kColors[cid].b);
      }
    }
    for (auto item : probetag.GetFilterPairs()) {
      node->AddSuspect(item);
      // 1.防御节点 2.收到防御包 3.该路径未被过滤 4.是一个不同对探测节点发送对信息
      if (node->GetFlag() == Node::kNodeFlag::FLAG_DEFEND &&
          probetag.GetFlag() == Node::kNodeFlag::FLAG_DEFEND &&
          (!node->IsAttacker(item)) &&
          (!node->IsReceivedDefendInfo(probetag.GetSendnid(), item))) {
        node->AddAttacker(item);
        node->AddReceivedDefendInfo(probetag.GetSendnid(), item);
        // std::cout << "receive defend packet" << std::endl;
        // std::cout << Names::FindName(node) << ": " << item.first << ">>>"
        //           << item.second << std::endl;
        if (node->IsAttacker(item)) {
          std::cout << "=======!!!!!!!=======" << std::endl;
          std::cout << Names::FindName(node) << ": " << item.first << ">>>"
                    << item.second << std::endl;
        }
      }
    }

    if (probetag.GetFlagTtl() >= 1) {
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
        filterPair pir = std::make_pair(nodeip, nexthop);
        if (node->IsAttacker(pir)) continue;

        // std::cout << "dst: " << item.first << ", rtte next hop: " << rtte.GetNextHop() << std::endl;
        // send special packet to neighbor
        double rnd = 1. * rand() / RAND_MAX;
        if (probetag.GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
            rnd > kProbProbeContinue)
          continue;
        if (probetag.GetFlag() == Node::kNodeFlag::FLAG_DEFEND &&
            rnd > kProbDefendContinue)
          continue;
        if (tmp.find(nexthop) != tmp.end()) continue;
        tmp.insert(nexthop);
        // std::cout << "node " << Names::FindName(sock->GetNode()) << " send to"
        //           << nexthop << std::endl;
        NS_LOG_DEBUG(Now() << " forward packet to " << nexthop);
        SendSpecialPacket(sock, InetSocketAddress(nexthop, kProbePort),
                          probetag.GetFlag(), probetag.GetFlagTtl() - 1,
                          probetag.GetSendnid(), probetag.GetPid(),
                          probetag.GetFilterPairs());
      }
      tmp.clear();
    }
  } else {
    // normal packet
    NS_LOG_DEBUG("???");
  }
}

void AodvSendDefendPacket(Ptr<Node> node, filterPair src2dst) {
  std::cout << Names::FindName(node) << ": send defend packet" << std::endl;
  std::cout << src2dst.first << ">>>" << src2dst.second << std::endl;
  Ptr<Socket> sock =
      Socket::CreateSocket(node, TypeId::LookupByName("ns3::UdpSocketFactory"));
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
  Ipv4Address nodeip = ipv4->GetAddress(1, 0).GetLocal();
  std::set<filterPair> S{src2dst};
  SendSpecialPacket(sock, InetSocketAddress(nodeip, kProbePort),
                    Node::kNodeFlag::FLAG_DEFEND, kDefendTtl, node->GetId(),
                    rand(), S);
}

void SendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl, uint32_t nid, uint32_t pid,
                       std::set<filterPair> filterpairs) {
  Ptr<Packet> p = Create<Packet>();
  // create a tag.
  MyTag tag;
  tag.SetFlag(flag);
  tag.SetFlagTtl(ttl);
  tag.SetSendnid(nid);
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
      uint32_t delta = item.second.rxBytes - rxMP[item.first];
      if (delta >= 64){
        num += delta;
        S.insert(tmp.sourceAddress);
      } 
      // NS_LOG_DEBUG(tmp.destinationAddress);
      // NS_LOG_DEBUG(item.second.rxPackets << " " <<rxMP[item.first]);
      rxMP[item.first] = item.second.rxBytes;
    }
  }
  if (num > (uint32_t)(kUpdateTime * kServerRate * kPacketSize)) {
    std::set<filterPair> S1;
    for (auto item : S) {
      NS_LOG_DEBUG("suspicious path: " << item << " >> " << nodeip);
      std::cout << Now() << ", "
                << "suspicious path: " << item << " >> " << nodeip << std::endl;
      S1.insert(std::make_pair(item, nodeip));
    }
    // Simulator::ScheduleNow(&SendSpecialPacket, sock,
    //                        InetSocketAddress(nodeip, kProbePort),
    //                        Node::kNodeFlag::FLAG_PROBE, kProbeTtl + 1, 1,
    //                        rand(), S1);  // 因为向自己发包故+1
    SendSpecialPacket(sock, InetSocketAddress(nodeip, kProbePort), Node::kNodeFlag::FLAG_PROBE,
                      kProbeTtl, sock->GetNode()->GetId(), rand(), S1);
  }
  Simulator::Schedule(Seconds(kUpdateTime), &ThroughputMonitor,
                      flowMonitorHelper, flowMonitor, sock, rxMP);
}

void UpdateNodeColor(NodeContainer nodes,
                     std::map<uint32_t, uint32_t> MPid2color, double interval) {
  // string dcrp("node convert to normal");
  for (uint32_t i = 0; i < nodes.GetN(); i++)
    if (nodes.Get(i)->GetFlag() == Node::kNodeFlag::FLAG_NORMAL) {
      uint32_t cid = MPid2color[i];
      // pAnim->UpdateNodeColor(nodes.Get(i), kColors[cid].r, kColors[cid].g, kColors[cid].b);
      // pAnim->UpdateNodeDescription(nodes.Get(i), dcrp);
    }
  Simulator::Schedule(Seconds(interval), &UpdateNodeColor, nodes, MPid2color,
                      interval);
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
  return sizeof(uint32_t) * 4 +
         sizeof(uint32_t) * (2 * m_filterpairs.size() + 1);
}
void MyTag::Serialize(TagBuffer buffer) const {
  buffer.WriteU32(m_flag);
  buffer.WriteU32(m_ttl);
  buffer.WriteU32(m_sendnid);
  buffer.WriteU32(m_pid);
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
  m_sendnid = buffer.ReadU32();
  m_pid = buffer.ReadU32();
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
void MyTag::SetSendnid(uint32_t nid) { m_sendnid = nid; }
uint32_t MyTag::GetSendnid(void) const { return m_sendnid; }
void MyTag::SetPid(uint32_t pid) { m_pid = pid; }
uint32_t MyTag::GetPid(void) const { return m_pid; }
void MyTag::SetFilterPairs(std::set<filterPair> pirs) { m_filterpairs = pirs; }
std::set<filterPair> MyTag::GetFilterPairs(void) { return m_filterpairs; }
