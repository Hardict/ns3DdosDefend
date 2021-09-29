#include <ctime>
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/ssid.h"
#include "ns3/tag.h"
#include "ns3/uinteger.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/olsr-helper.h"

using namespace std;
using namespace ns3;

NS_LOG_COMPONENT_DEFINE("MySocket");
const double kProb = 0.8;
const uint32_t kProbeTag = 1;

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
   * Set the tag value
   * \param value The tag value.
   */
  void SetTag(uint32_t value);
  /**
   * Get the tag value
   * \return the tag value.
   */
  uint32_t GetTag(void) const;
  /**
   * Set the ttl value
   * \param ttl The ttl value.
   */
  void SetTtl(uint32_t ttl);
  /**
   * Get the ttl value
   * \return the ttl value.
   */
  uint32_t GetTtl(void) const;

 private:
  uint32_t m_tagValue;
  uint32_t m_ttl;  // Time To Live
};

static void recvCallback(Ptr<Socket> sock);
void sendWithProbeTag(Ptr<Socket> sock, Ptr<Packet> pck);
void sendWithTag1(Ptr<Socket> sock);
void sendWithTag2(Ptr<Socket> sock);

int main(int argc, char *argv[]) {
  CommandLine cmd(__FILE__);
  cmd.Parse(argc, argv);

  srand(time(NULL));
  uint32_t nAdHoc = 30;
  cmd.AddValue ("nAdHoc", "Number of wifi ad devices", nAdHoc);
  NodeContainer AdHocNode;
  AdHocNode.Create(nAdHoc);

  YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper phy;
  phy.SetChannel (channel.Create ());

  WifiHelper wifi;
  // wifi.SetStandard(WIFI_PHY_STANDARD_80211a); //设置标准
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager","DataMode",StringValue("OfdmRate6Mbps"));

  WifiMacHelper mac;
  mac.SetType ("ns3::AdhocWifiMac");

  NetDeviceContainer AdHocDevices;
  AdHocDevices = wifi.Install(phy,mac,AdHocNode);

  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                    "MinX", DoubleValue (0.0),
                                    "MinY", DoubleValue (0.0),
                                    "DeltaX", DoubleValue (50.0),
                                    "DeltaY", DoubleValue (50.0),
                                    "GridWidth", UintegerValue (10),
                                    "LayoutType", StringValue ("RowFirst"));

  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                                "Bounds", RectangleValue (Rectangle (-5000, 5000, -5000, 5000)));
  mobility.Install (AdHocNode);

  // Enable OLSR
  OlsrHelper olsr;
  Ipv4StaticRoutingHelper staticRouting;
  Ipv4ListRoutingHelper list;
  list.Add (staticRouting, 0);
  list.Add (olsr, 10);
  
  InternetStackHelper internet;
  internet.SetRoutingHelper (list);
  internet.Install(AdHocNode);

  Ipv4AddressHelper address;
  address.SetBase("195.1.1.0","255.255.255.0");

  Ipv4InterfaceContainer AdHocIp;
  AdHocIp = address.Assign(AdHocDevices);

  // Receiver sockets
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  Ptr<Socket> recvSink1 = Socket::CreateSocket(
      AdHocNode.Get(0), tid);
  InetSocketAddress local1 = InetSocketAddress(Ipv4Address::GetAny(), 9);
  recvSink1->Bind(local1);
  recvSink1->SetRecvCallback(MakeCallback(&recvCallback));

  Ptr<Socket> recvSink2 = Socket::CreateSocket(
      AdHocNode.Get(5), tid);
  InetSocketAddress local2 = InetSocketAddress(Ipv4Address::GetAny(), 9);
  recvSink2->Bind(local2);
  recvSink2->SetRecvCallback(MakeCallback(&recvCallback));

  // Sender sockets
  Ptr<Socket> source1 =
      Socket::CreateSocket(AdHocNode.Get(20), tid);  //设置ApNode为发送源
  InetSocketAddress remote_0 =
      InetSocketAddress(Ipv4Address::GetBroadcast(), 9);  //广播群发
  source1->SetAllowBroadcast(true);                       //开启广播
  source1->Connect(remote_0);  //用广播地址发包

  Ptr<Socket> source2 = Socket::CreateSocket(AdHocNode.Get(25), tid);
  InetSocketAddress remote_1 =
      InetSocketAddress(Ipv4Address::GetBroadcast(), 9);  //广播群发
  source2->SetAllowBroadcast(true);                       //开启广播
  source2->Connect(remote_1);  //用广播地址发包

  Simulator::Schedule(Seconds(1.0), &sendWithTag1, source1);
  Simulator::Schedule(Seconds(2.0), &sendWithTag2, source2);

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
          .AddAttribute("tagValue", "packet tag value", EmptyAttributeValue(),
                        MakeUintegerAccessor(&MyTag::GetTag),
                        MakeUintegerChecker<uint32_t>());
  return tid;
}
TypeId MyTag::GetInstanceTypeId(void) const { return GetTypeId(); }
uint32_t MyTag::GetSerializedSize(void) const { return sizeof(uint32_t) * 2; }
void MyTag::Serialize(TagBuffer i) const {
  i.WriteU32(m_tagValue);
  i.WriteU32(m_ttl);
}
void MyTag::Deserialize(TagBuffer i) {
  m_tagValue = i.ReadU32();
  m_ttl = i.ReadU32();
}
void MyTag::Print(std::ostream &os) const {
  os << "v=" << (uint32_t)m_tagValue;
}
void MyTag::SetTag(uint32_t value) { m_tagValue = value; }
uint32_t MyTag::GetTag(void) const { return m_tagValue; }
void MyTag::SetTtl(uint32_t ttl) { m_ttl = ttl; }
uint32_t MyTag::GetTtl(void) const { return m_ttl; }

//回调函数
static void recvCallback(Ptr<Socket> sock) {
  Ptr<Packet> packet = sock->Recv();

  MyTag tagCopy;
  packet->PeekPacketTag(tagCopy);

  uint32_t v_tag = tagCopy.GetTag();
  uint32_t v_ttl = tagCopy.GetTtl();

  // if (tag == 0x56)
  {
    cout << "received a packet!" << endl;
    cout << "tag:" << v_tag << endl;
    cout << "ttl:" << v_ttl << endl;
    cout << "packet_size:" << packet->GetSize()<< endl;
  }

  if (v_tag == kProbeTag) {
    cout << "get probe packet" << endl;
    if (1.0 * rand() / RAND_MAX < kProb) {
      // 节点变为探测节点
      if (v_ttl) {
        MyTag new_tag;
        new_tag.SetTag(v_tag);
        new_tag.SetTtl(v_ttl - 1);
        Ptr<Packet> pck = Create<Packet>(1);
        pck->AddPacketTag(new_tag);
        SocketIpTtlTag ttl_tag;
        ttl_tag.SetTtl(2);
        pck->AddPacketTag(ttl_tag);
        InetSocketAddress broadcast =
            InetSocketAddress(Ipv4Address::GetBroadcast(), 9);
        sock->Connect(broadcast);
        cout<<Now().GetSeconds()<<endl;
        Simulator::Schedule(Now(), &sendWithProbeTag, sock, pck);
      }
    }
  } else {
    // 普通包
    // NS_LOG_INFO("get normal packet");
  }
  cout<<endl;
}

void sendWithProbeTag(Ptr<Socket> sock, Ptr<Packet> pck) { sock->Send(pck); };

void sendWithTag1(Ptr<Socket> sock) {
  // create a tag.
  MyTag tag;
  tag.SetTag(0x1);
  tag.SetTtl(0x3);
  // cout << "origin:" << tag.GetTag() << endl;

  // store the tag in a packet.
  Ptr<Packet> p = Create<Packet>(100);
  p->AddPacketTag(tag);
  sock->Send(p);
}

void sendWithTag2(Ptr<Socket> sock) {
  // create a tag.
  MyTag tag;
  tag.SetTag(0x0);
  tag.SetTtl(0x3);
  // store the tag in a packet.
  Ptr<Packet> p = Create<Packet>(200);
  p->AddPacketTag(tag);
  sock->Send(p);
}
