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

NS_LOG_COMPONENT_DEFINE("HardictStaticRouting");

const double kProb = 1;
const uint32_t kProbeTag = 1;
const uint32_t kDefendTag = 2;
const uint32_t kFlagPort = 2333;
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

  LogComponentEnable("HardictStaticRouting", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

  uint32_t nAdHoc = 10;

  CommandLine cmd;

  // cmd.AddValue("nAdHoc", "Number of wifi ad devices", nAdHoc);
  cmd.Parse(argc, argv);

  NodeContainer AdHocNode;
  AdHocNode.Create(nAdHoc);

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
  channel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange",
                             DoubleValue(50.0));
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
  Ptr<ListPositionAllocator> positionAlloc =
      CreateObject<ListPositionAllocator>();
  positionAlloc->Add(Vector(0, 10, 3.0));
  positionAlloc->Add(Vector(100, 10, 3.0));
  positionAlloc->Add(Vector(32, 20, 3.0));
  positionAlloc->Add(Vector(78, 23, 3.0));
  positionAlloc->Add(Vector(66, 44, 3.0));
  positionAlloc->Add(Vector(50, 50, 3.0));
  positionAlloc->Add(Vector(88, 66, 3.0));
  positionAlloc->Add(Vector(23, 68, 3.0));
  positionAlloc->Add(Vector(46, 76, 3.0));
  positionAlloc->Add(Vector(77, 100, 3.0));
  mobility.SetPositionAllocator(positionAlloc);
  // mobility.SetMobilityModel( "ns3::RandomWalk2dMobilityModel", "Bounds",
  // RectangleValue(Rectangle(-5000, 5000, -5000, 5000)));
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(AdHocNode);

  Ipv4StaticRoutingHelper staticRoutingHelper;

  InternetStackHelper internet;
  internet.SetRoutingHelper(staticRoutingHelper);
  internet.Install(AdHocNode);

  Ipv4AddressHelper address;
  address.SetBase("195.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer AdHocIp;
  AdHocIp = address.Assign(AdHocDevices);

  // 1->{3}
  Ptr<Ipv4StaticRouting> staticRouting;
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(0)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(2), AdHocIp.GetAddress(2),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(2), 1);

  // 2->{4}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(1)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(3), AdHocIp.GetAddress(3),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(3), 1);

  // 3->{1,6}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(2)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(0), AdHocIp.GetAddress(0),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5), AdHocIp.GetAddress(5),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(5), 1);

  // 4->{2,5,6}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(3)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(1), AdHocIp.GetAddress(1),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(4), AdHocIp.GetAddress(4),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5), AdHocIp.GetAddress(5),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(5), 1);

  // 5->{4,6,7}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(4)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(3), AdHocIp.GetAddress(3),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5), AdHocIp.GetAddress(5),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(6), AdHocIp.GetAddress(6),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(5), 1);

  // 6->{3,5,8,9}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(5)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(2), AdHocIp.GetAddress(2),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(4), AdHocIp.GetAddress(4),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(7), AdHocIp.GetAddress(7),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(8), AdHocIp.GetAddress(8),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.252"),
                                   AdHocIp.GetAddress(2), 1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.4"),
                                   Ipv4Mask("255.255.255.252"),
                                   AdHocIp.GetAddress(3), 1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.8"),
                                   Ipv4Mask("255.255.255.252"),
                                   AdHocIp.GetAddress(8), 1);

  // 7->{5}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(6)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(4), AdHocIp.GetAddress(4),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(4), 1);

  // 8->{6,9}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(7)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5), AdHocIp.GetAddress(5),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(8), AdHocIp.GetAddress(8),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(5), 1);

  // 9->{8,6,10}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(8)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5), AdHocIp.GetAddress(5),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(7), AdHocIp.GetAddress(7),
                                1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(9), AdHocIp.GetAddress(9),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(5), 1);

  // 10->{9}
  staticRouting =
      staticRoutingHelper.GetStaticRouting(AdHocNode.Get(9)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(8), AdHocIp.GetAddress(8),
                                1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"),
                                   Ipv4Mask("255.255.255.0"),
                                   AdHocIp.GetAddress(8), 1);


  NS_LOG_INFO("Create Applications.");
  uint32_t port = 2333;
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for(uint32_t i=0;i<AdHocNode.GetN();i++){
    Ptr<Socket> recvSocket = Socket::CreateSocket(AdHocNode.Get(i), tid);
    recvSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), port));
    recvSocket->SetRecvCallback(MakeCallback(&recvCallback));
  }

  Ptr<Socket> source = Socket::CreateSocket(AdHocNode.Get(9), tid);
  // source->Connect(InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)),port));

  Simulator::Schedule(
      Seconds(2.), &sendWithTag1, source, AdHocIp.GetAddress(9),
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(0)), port));
  Simulator::Schedule(
      Seconds(5.), &sendWithTag2, source, AdHocIp.GetAddress(9),
      InetSocketAddress(Ipv4Address(AdHocIp.GetAddress(2)), port));

  AsciiTraceHelper ascii;
  phy.EnableAsciiAll(ascii.CreateFileStream("1-phy.tr"));
  phy.EnablePcap("1-phy", AdHocDevices);
  internet.EnableAsciiIpv4All(ascii.CreateFileStream("1-ip.tr"));
  internet.EnablePcapIpv4("1-ip", AdHocNode);
  Ptr<OutputStreamWrapper> routingStream =
      Create<OutputStreamWrapper>("1.routes", std::ios::out);
  staticRoutingHelper.PrintRoutingTableAllEvery(Seconds(0.5), routingStream);

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
          .AddAttribute("FlagTtlValue", "packet Flag Ttl",
                        EmptyAttributeValue(),
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
void MyTag::Print(std::ostream &os) const { os << "v=" << (uint32_t)m_flag; }
void MyTag::SetFlag(uint32_t value) { m_flag = value; }
uint32_t MyTag::GetFlag(void) const { return m_flag; }
void MyTag::SetFlagTtl(uint32_t ttl) { m_ttl = ttl; }
uint32_t MyTag::GetFlagTtl(void) const { return m_ttl; }

void sendSpecailPacket(Ptr<Socket> sock, Ptr<Packet> packet, InetSocketAddress dst);
static void recvCallback(Ptr<Socket> sock) {
  Ptr<Packet> packet = sock->Recv()->Copy();

  MyTag org_tag;
  packet->PeekPacketTag(org_tag);

  uint32_t v_flag = org_tag.GetFlag();
  uint32_t v_ttl = org_tag.GetFlagTtl();
  Ipv4Header header;
  packet->PeekHeader(header);

  {
    header.GetDestination().Print(std::cout);
    std::cout << " received a packet! from ";
    header.GetSource().Print(std::cout);
    std::cout << std::endl;
    std::cout << "flag:" << v_flag << std::endl;
    std::cout << "ttl:" << v_ttl << std::endl;
    std::cout << "packet_size:" << packet->GetSize() << std::endl;
  }

  Ptr<Node> node = sock->GetNode();
  Ptr<Ipv4L3Protocol> ipl3p = node->GetObject<Ipv4L3Protocol>();
  Ptr<Ipv4RoutingProtocol> iprtp = ipl3p->GetRoutingProtocol();
  Ptr<Ipv4StaticRouting> staticRouting = Ipv4StaticRoutingHelper::GetRouting<Ipv4StaticRouting>(iprtp);
  staticRouting->PrintRoutingTable(Create<OutputStreamWrapper>("test.routes", std::ios::out));
  if (org_tag.GetFlag() == kProbeTag) {
    // probe tag packet
    if (node->GetFlag() != kDefendTag) {
      node->SetFlag(kProbeTag);
      for (uint32_t i = 0; i < staticRouting->GetNRoutes(); i++) {
        // item.first.Print(std::cout);
        auto rtte = staticRouting->GetRoute(i);
        Ipv4Address dst = rtte.GetGateway();
        if (dst.IsAny() || dst.IsLocalhost() || dst.IsBroadcast() ||
            dst.IsSubnetDirectedBroadcast(Ipv4Mask("255.255.255.0")))
          continue;

        // send probe packet to neighbor
        if (1.0 * rand() / RAND_MAX < kProb && org_tag.GetFlagTtl() > 1) {
          Ptr<Packet> pp = Create<Packet>();
          // SocketIpTtlTag ipttltag;
          // ipttltag.SetTtl(1);
          // pp->AddPacketTag(ipttltag);
          MyTag mytag;
          mytag.SetFlag(org_tag.GetFlag());
          mytag.SetFlagTtl(org_tag.GetFlagTtl() - 1);
          pp->AddPacketTag(mytag);
          Ipv4Header header;
          header.SetTtl(1);
          header.SetDestination(dst);
          header.SetSource(node->GetObject<Ipv4>()->GetAddress(rtte.GetInterface(), 0).GetLocal());
          pp->AddHeader(header);
          // header.Print(std::cout);
          // sock->SendTo(pp,0,dst);

          // std::cout << "send probe packet" << std::endl;
          // std::cout << Now().GetSeconds() << std::endl;
          TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
          Ptr<Socket> tmpsock = Socket::CreateSocket(sock->GetNode(), tid);
          tmpsock->SetIpTtl(1);
          Simulator::ScheduleNow(sendSpecailPacket, tmpsock, pp, InetSocketAddress(dst,kFlagPort));
          // header.Print(std::cout);
        }
      }
    }
  } else if (org_tag.GetFlag() == kDefendTag) {
    // defend tag packet
    node->SetFlag(kDefendTag);
  } else {
    // normal packet
  }
}

void sendWithTag1(Ptr<Socket> sock, Ipv4Address src, InetSocketAddress dst) {
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

void sendSpecailPacket(Ptr<Socket> sock, Ptr<Packet> packet, InetSocketAddress dst) {
  std::cout << "???"  << std::endl;
  sock->SendTo(packet, 0, dst);
}