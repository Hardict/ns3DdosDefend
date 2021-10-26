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

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("MyCode");

const double kProbContinue = 1.;
const double kProbeNew = 1.;
//Node::kNodeFlag::FLAG_NORMAL = 0;
//Node::kNodeFlag::FLAG_PROBE = 1;
//Node::kNodeFlag::FLAG_DEFEND = 2;
const uint32_t kProbePort = 2333;
const uint32_t kProbeTtl = 2;
const uint32_t kDefendTtl = 2;
const uint32_t kMaxPacketsEverySeconds = 2;  // 每秒至多发1个包
// 每1s更新一次
const double kUpdateTime = 0.5;
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
void printkNodeFlag(NodeContainer nodes){
    std::stringstream stmp;
    for(uint32_t i = 0;i < nodes.GetN(); i++) stmp << nodes.Get(i)->GetFlag() << " ";
    // NS_LOG_DEBUG(stmp.str());
}

int main(int argc, char *argv[]) {
  Time::SetResolution(Time::NS);

  LogComponentEnable("MyCode", LOG_LEVEL_INFO);
  // LogComponentEnable ("TcpL4Protocol", LOG_LEVEL_INFO);
  // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  // LogComponentEnable("AodvRoutingTable", LOG_LEVEL_ALL);
  // LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

  uint32_t nAdHocNum = 10;
  uint32_t nStep = 50;
  uint32_t nSeed = 1;

  CommandLine cmd;
  cmd.AddValue("nAdHocNum", "Number of wifi ad devices", nAdHocNum);
  cmd.AddValue("nStep", "distance between two node", nStep);
  cmd.AddValue("nSeed", "random seed", nSeed);
  cmd.Parse(argc, argv);
  srand((unsigned)time(nullptr));
  cout<<rand()<<endl;

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
  RngSeedManager::SetSeed(nSeed);
  mobility.SetPositionAllocator(
      "ns3::GridPositionAllocator", "MinX", DoubleValue(0.0), "MinY",
      DoubleValue(0.0), "DeltaX", DoubleValue(nStep), "DeltaY", DoubleValue(0),
      "GridWidth", UintegerValue(nAdHocNum), "LayoutType",
      StringValue("RowFirst"));
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(AdHocNodes);

  AodvHelper aodv;
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

  uint32_t normalport = 9;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for (uint32_t i = 0; i < AdHocNodes.GetN(); i++) {
    Ptr<Socket> recvProbeSocket = Socket::CreateSocket(AdHocNodes.Get(i), tid);
    recvProbeSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), kProbePort));
    recvProbeSocket->SetRecvCallback(MakeCallback(&recvProbeCallback));
    Ptr<Socket> recvNormalSocket = Socket::CreateSocket(AdHocNodes.Get(i), tid);
    recvNormalSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), normalport));
    recvNormalSocket->SetRecvCallback(MakeCallback(&recvNormalCallback));
  }

  // Node[n-1] >> Node[0]
  Ptr<Socket> sourceProbeSocket =
      Socket::CreateSocket(AdHocNodes.Get(nAdHocNum - 1), tid);
  sourceProbeSocket->Connect(
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), kProbePort));
  Ptr<Socket> sourceNormalSocket =
      Socket::CreateSocket(AdHocNodes.Get(nAdHocNum - 1), tid);
  sourceNormalSocket->Connect(
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), normalport));

  // test special packet
  std::set<filterPair> filterpairs;
  filterpairs.insert(std::make_pair(Ipv4Address("123.234.5.6"), Ipv4Address("1.2.3.4")));
  filterpairs.insert(std::make_pair(Ipv4Address("45.38.51.69"), Ipv4Address("4.3.2.1")));
  Simulator::Schedule(
      Seconds(2.), &sendSpecialPacket, sourceProbeSocket,
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), kProbePort),
      Node::kNodeFlag::FLAG_PROBE, 3, 3,
      filterpairs);

  // Simulator::Schedule(
  //     Seconds(2.), &sendNormalPacket, sourceNormalSocket,
  //     InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), normalport),
  //     100, Seconds(0.5));
  // for (int i=0;i<100;i++) Simulator::Schedule(Seconds(2.+0.5*i), &printkNodeFlag, AdHocNodes);

  // phy.EnablePcap("rgg2", AdHocDevices);

  Simulator::Stop(Seconds(20.));
  Simulator::Run();
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
          Simulator::Schedule(Seconds(kUpdateTime*rand()/RAND_MAX),
                              sendSpecialPacket, sock,
                              InetSocketAddress(nexthop, kProbePort),
                              org_tag.GetFlag(), org_tag.GetFlagTtl() - 1,
                              org_tag.GetPid(), org_tag.GetFilterPairs());
        }
        // send new defend packet to neighbor
        if (org_tag.GetFlag() == Node::kNodeFlag::FLAG_PROBE &&
            1.0 * rand() / RAND_MAX < kProbeNew) {
          if (tmp.find(nexthop) != tmp.end()) continue;
          tmp.insert(nexthop);
          NS_LOG_DEBUG(Now() << " send Defend packet to " << nexthop);
          Simulator::Schedule(
              Seconds(kUpdateTime*rand()/RAND_MAX),
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
    // node->AddSuspect(org_tag.GetFilterPair());
  } else {
    // normal packet
    NS_LOG_DEBUG("???");
  }
}

void sendSpecialPacket(Ptr<Socket> sock, InetSocketAddress dst, uint32_t flag,
                       uint32_t ttl,uint32_t pid, std::set<filterPair> filterpairs) {
  Ptr<Packet> p = Create<Packet>();
  // create a tag.
  NS_LOG_DEBUG(Now());
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
  std::cout << m_filterpairs.size() << std::endl;
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
