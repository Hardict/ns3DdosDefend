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
  channel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange", DoubleValue(50.0));
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
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (0, 10, 3.0));
  positionAlloc->Add (Vector (100, 10, 3.0));
  positionAlloc->Add (Vector (32, 20, 3.0));
  positionAlloc->Add (Vector (78, 23, 3.0));
  positionAlloc->Add (Vector (66, 44, 3.0));
  positionAlloc->Add (Vector (50, 50, 3.0));
  positionAlloc->Add (Vector (88, 66, 3.0));
  positionAlloc->Add (Vector (23, 68, 3.0));
  positionAlloc->Add (Vector (46, 76, 3.0));
  positionAlloc->Add (Vector (77, 100, 3.0));
  mobility.SetPositionAllocator (positionAlloc);
  // mobility.SetMobilityModel( "ns3::RandomWalk2dMobilityModel", "Bounds", RectangleValue(Rectangle(-5000, 5000, -5000, 5000)));
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

  //1->{3}
  Ptr<Ipv4StaticRouting> staticRouting;
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(0)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(2),AdHocIp.GetAddress(2),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"), AdHocIp.GetAddress(2), 1);
  
  //2->{4}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(1)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(3),AdHocIp.GetAddress(3),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"), AdHocIp.GetAddress(3), 1);
  
  //3->{1,6}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(2)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(0),AdHocIp.GetAddress(0),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5),AdHocIp.GetAddress(5),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"), AdHocIp.GetAddress(5), 1);
  
  //4->{2,5,6}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(3)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(1),AdHocIp.GetAddress(1),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(4),AdHocIp.GetAddress(4),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5),AdHocIp.GetAddress(5),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"), AdHocIp.GetAddress(5), 1);
  
  //5->{4,6,7}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(4)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(3),AdHocIp.GetAddress(3),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5),AdHocIp.GetAddress(5),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(6),AdHocIp.GetAddress(6),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"),AdHocIp.GetAddress(5), 1);
  
  //6->{3,5,8,9}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(5)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(2),AdHocIp.GetAddress(2),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(4),AdHocIp.GetAddress(4),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(7),AdHocIp.GetAddress(7),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(8),AdHocIp.GetAddress(8),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.252"),AdHocIp.GetAddress(2), 1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.4"), Ipv4Mask("255.255.255.252"),AdHocIp.GetAddress(3), 1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.8"), Ipv4Mask("255.255.255.252"),AdHocIp.GetAddress(8), 1);

  //7->{5}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(6)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(4),AdHocIp.GetAddress(4),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"),AdHocIp.GetAddress(4),1);

  //8->{6,9}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(7)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5),AdHocIp.GetAddress(5),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(8),AdHocIp.GetAddress(8),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"),AdHocIp.GetAddress(5),1);

  //9->{8,6,10}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(8)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(5),AdHocIp.GetAddress(5),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(7),AdHocIp.GetAddress(7),1);
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(9),AdHocIp.GetAddress(9),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"),AdHocIp.GetAddress(5),1);

  //10->{9}
  staticRouting = staticRoutingHelper.GetStaticRouting(AdHocNode.Get(9)->GetObject<Ipv4>());
  staticRouting->AddHostRouteTo(AdHocIp.GetAddress(8),AdHocIp.GetAddress(8),1);
  staticRouting->AddNetworkRouteTo(Ipv4Address("195.1.1.0"), Ipv4Mask("255.255.255.0"),AdHocIp.GetAddress(8),1);


  UdpEchoServerHelper echoServer(9);

  ApplicationContainer serverApps = echoServer.Install(AdHocNode.Get(0));
  serverApps.Start(Seconds(1.0));
  serverApps.Stop(Seconds(10.0));

  UdpEchoClientHelper echoClient(AdHocIp.GetAddress(0), 9);
  echoClient.SetAttribute("MaxPackets", UintegerValue(2));
  echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
  echoClient.SetAttribute("PacketSize", UintegerValue(1024));

  ApplicationContainer clientApps = echoClient.Install(AdHocNode.Get(5));
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(10.0));

  AsciiTraceHelper ascii;
  phy.EnableAsciiAll(ascii.CreateFileStream("1-phy.tr"));
  phy.EnablePcap ("1-phy", AdHocDevices);
  internet.EnableAsciiIpv4All(ascii.CreateFileStream("1-ip.tr"));
  internet.EnablePcapIpv4 ("1-ip",AdHocNode);
  Ptr<OutputStreamWrapper> routingStream =
      Create<OutputStreamWrapper>("1-phy.routes", std::ios::out);
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