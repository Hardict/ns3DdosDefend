#include <bits/stdc++.h>
#include "ns3/aodv-helper.h"
#include "ns3/aodv-routing-protocol.h"
#include "ns3/aodv-rtable.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-helper.h"
#include "ns3/wifi-module.h"

using namespace ns3;
using namespace std;

NS_LOG_COMPONENT_DEFINE("AdHocExample");

const double kProb = 1;
const uint32_t kProbeTag = 1;
const uint32_t kDefendTag = 2;
class MyTag : public Tag {
 public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId(void);
  virtual TypeId GetInstanceTypeId(void) const;
  virtual uint32_t GetSerializedSize(void) const;
  virtual void Serialize(TagBuffer i) const;
  virtual void Deserialize(TagBuffer i);
  virtual void Print(std::ostream &os) const;

  /**
   * Set the flag value
   * \param value The tag value.
   */
  void SetFlag(uint32_t value);
  /**
   * Get the tag value
   * \return the tag value.
   */
  uint32_t GetFlag(void) const;
  /**
   * Set the ttl value
   * \param ttl The ttl value.
   */
  void SetFlagTtl(uint32_t ttl);
  /**
   * Get the ttl value
   * \return the ttl value.
   */
  uint32_t GetFlagTtl(void) const;

 private:
  uint32_t m_flag;
  uint32_t m_ttl;  // Time To Live
};

static void recvCallback(Ptr<Socket> sock);
void sendWithTag1(Ptr<Socket> sock, Ipv4Address src, InetSocketAddress dst);
void sendWithTag2(Ptr<Socket> sock, Ipv4Address src, InetSocketAddress dst);

int main(int argc, char *argv[]) {
  Time::SetResolution(Time::NS);

  LogComponentEnable("AdHocExample", LOG_LEVEL_INFO);
  // LogComponentEnable ("TcpL4Protocol", LOG_LEVEL_INFO);
  LogComponentEnable("PacketSink", LOG_LEVEL_ALL);

  uint32_t nAdHoc = 30;

  CommandLine cmd;

  cmd.AddValue("nAdHoc", "Number of wifi ad devices", nAdHoc);

  cmd.Parse(argc, argv);

  NodeContainer AdHocNode;
  AdHocNode.Create(nAdHoc);

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(channel.Create());

  WifiHelper wifi;
  // wifi.SetStandard(WIFI_PHY_STANDARD_80211a); //设置标准
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
                               StringValue("OfdmRate6Mbps"));

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer AdHocDevices;
  AdHocDevices = wifi.Install(phy, mac, AdHocNode);

  MobilityHelper mobility;
  mobility.SetPositionAllocator(
      "ns3::GridPositionAllocator", "MinX", DoubleValue(0.0), "MinY",
      DoubleValue(0.0), "DeltaX", DoubleValue(50.0), "DeltaY",
      DoubleValue(50.0), "GridWidth", UintegerValue(10), "LayoutType",
      StringValue("RowFirst"));

  mobility.SetMobilityModel(
      "ns3::RandomWalk2dMobilityModel", "Bounds",
      RectangleValue(Rectangle(-5000, 5000, -5000, 5000)));
  mobility.Install(AdHocNode);

  AodvHelper aodv;
  Ipv4StaticRoutingHelper staticRouting;
  Ipv4ListRoutingHelper list;
  list.Add(staticRouting, 0);
  list.Add(aodv, 10);

  InternetStackHelper internet;
  internet.SetRoutingHelper(list);
  internet.Install(AdHocNode);

  Ipv4AddressHelper address;
  address.SetBase("195.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer AdHocIp;
  AdHocIp = address.Assign(AdHocDevices);

  NS_LOG_INFO("Create Applications.");
  uint32_t port = 2333;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for(uint32_t i=0;i<AdHocNode.GetN();i++){
    Ptr<Socket> recvSocket = Socket::CreateSocket(AdHocNode.Get(i), tid);
    recvSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
    recvSocket->SetRecvCallback(MakeCallback(&recvCallback));
  }

  Ptr<Socket> source = Socket::CreateSocket(AdHocNode.Get(14), tid);
  source->Connect(InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)),port));

  Simulator::Schedule(
      Seconds(2.), &sendWithTag1, source, AdHocIp.GetAddress(14),
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), port));
  Simulator::Schedule(
      Seconds(5.), &sendWithTag2, source, AdHocIp.GetAddress(14),
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), port));

  phy.EnablePcap ("rgg2", AdHocDevices);
  Ptr<OutputStreamWrapper> routingStream =
      Create<OutputStreamWrapper>("rgg2.routes", std::ios::out);
  aodv.PrintRoutingTableAllEvery(Seconds(0.5), routingStream);
  Ptr<OutputStreamWrapper> neighborStream =
      Create<OutputStreamWrapper>("rgg2.neighbors", std::ios::out);
  aodv.PrintNeighborCacheAllEvery(Seconds(0.5), neighborStream);

  Simulator::Stop(Seconds(10.0));
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}

TypeId MyTag::GetTypeId(void) {
  static TypeId tid =
      TypeId("ns3::MyTag")
          .SetParent<Tag>()
          .AddConstructor<MyTag>()
          .AddAttribute("FlagValue", "packet flag value", EmptyAttributeValue(),
                        MakeUintegerAccessor(&MyTag::GetFlag),
                        MakeUintegerChecker<uint32_t>())
          .AddAttribute("FlagTtlValue", "packet Flag Ttl", EmptyAttributeValue(),
                        MakeUintegerAccessor(&MyTag::GetFlagTtl),
                        MakeUintegerChecker<uint32_t>());
  return tid;
}
TypeId MyTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t MyTag::GetSerializedSize(void) const { return sizeof(uint32_t) * 2; }
void MyTag::Serialize(TagBuffer i) const {
  i.WriteU32(m_flag);
  i.WriteU32(m_ttl);
}
void MyTag::Deserialize(TagBuffer i) {
  m_flag = i.ReadU32();
  m_ttl = i.ReadU32();
}
void MyTag::Print(std::ostream &os) const {
  os << "v=" << (uint32_t)m_flag;
}
void MyTag::SetFlag(uint32_t value) { m_flag = value; }
uint32_t MyTag::GetFlag(void) const { return m_flag; }
void MyTag::SetFlagTtl(uint32_t ttl) { m_ttl = ttl; }
uint32_t MyTag::GetFlagTtl(void) const { return m_ttl; }

//回调函数
void sendSpecailPacket(Ptr<Socket> sock, Ptr<Packet> packet, Ipv4Address dst);
static void recvCallback(Ptr<Socket> sock) {
  Ptr<Packet> packet = sock->Recv()->Copy();

  MyTag org_tag;
  packet->PeekPacketTag(org_tag);

  uint32_t v_flag = org_tag.GetFlag();
  uint32_t v_ttl = org_tag.GetFlagTtl();
  Ipv4Header header;
  packet->PeekHeader(header);

  {
    std::cout << "received a packet! from ";
    header.GetSource().Print(std::cout);
    std::cout << std::endl;
    std::cout << "flag:" << v_flag << std::endl;
    std::cout << "ttl:" << v_ttl << std::endl;
    std::cout << "packet_size:" << packet->GetSize() << std::endl;
  }

  // // Ptr<Node> tmp = NodeList::GetNode(Simulator::GetContext());
  Ptr<Node> node = sock->GetNode();
  Ptr<Ipv4L3Protocol> ipl3p = node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
  Ptr<aodv::RoutingProtocol> aodv_rtp = AodvHelper::GetRouting<aodv::RoutingProtocol>(iprtp);
  aodv::RoutingTable aodv_rtt = aodv_rtp->GetRoutingTable();
  aodv_rtt.Print(Create<OutputStreamWrapper>("test.routes", std::ios::out));
  // aodv::RoutingTableEntry rtte;
  // aodv_rtt.LookupRoute(Ipv4Address("195.1.1.11"),rtte);
  // rtte.Print(Create<OutputStreamWrapper>("test.routes", std::ios::out));
  if(org_tag.GetFlag()==kProbeTag){
    //probe tag packet
    if(node->GetTag()!=kDefendTag){
      node->SetTag(kProbeTag);
      auto mp = aodv_rtt.GetMap();
      for(auto item: mp){
        // item.first.Print(std::cout);
        Ipv4Address dst = item.first;
        aodv::RoutingTableEntry rtte = item.second;
        if(dst.IsLocalhost()||dst.IsBroadcast()||dst.IsSubnetDirectedBroadcast(Ipv4Mask("255.255.255.0")))
        continue;
        
        // send probe packet to neighbor
        if(1.0*rand()/RAND_MAX < kProb && org_tag.GetFlagTtl()>1){
          Ptr<Packet> pp = Create<Packet>();
          // SocketIpTtlTag ipttltag;
          // ipttltag.SetTtl(1);
          // pp->AddPacketTag(ipttltag);
          MyTag mytag;
          mytag.SetFlag(org_tag.GetFlag());
          mytag.SetFlagTtl(org_tag.GetFlagTtl()-1);
          pp->AddPacketTag(mytag);
          Ipv4Header header;
          header.SetTtl(1);
          header.SetDestination(dst);
          header.SetSource(rtte.GetInterface().GetLocal());
          // sock->SendTo(pp,0,dst);
          std::cout<<"send probe packet"<<std::endl;
          std::cout<<Now().GetSeconds()<<std::endl;
          Simulator::ScheduleNow(sendSpecailPacket,sock,pp,dst);
          // header.Print(std::cout);
        }
      }
    }
  }else if(org_tag.GetFlag()==kDefendTag){
    //defend tag packet
    node->SetTag(kDefendTag);
  }else{
    //normal packet
  }
}

void sendWithTag1(Ptr<Socket> sock, Ipv4Address src, InetSocketAddress dst){
  Ptr<Packet> p = Create<Packet>();
  // create a tag.
  MyTag tag;
  tag.SetFlag(kProbeTag);
  tag.SetFlagTtl(0x5);
  p->AddPacketTag(tag);

  Ipv4Header header;
  header.SetSource(src);
  header.SetDestination(dst.GetIpv4());
  p->AddHeader(header);
  
  sock->SendTo(p, 0, dst);
}

void sendWithTag2(Ptr<Socket> sock, Ipv4Address src, InetSocketAddress dst) {
  // create a tag.
  MyTag tag;
  tag.SetFlag(0x56);
  tag.SetFlagTtl(0x5);
  // store the tag in a packet.
  Ptr<Packet> p = Create<Packet>(200);
  p->AddPacketTag(tag);
  sock->SendTo(p, 0, dst);
}

void sendSpecailPacket(Ptr<Socket> sock, Ptr<Packet> packet, Ipv4Address dst){
  std::cout<<"???"<<std::endl;
  sock->SendTo(packet,0,dst);
}