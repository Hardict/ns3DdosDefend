/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"

// Default Network Topology
//
//       10.1.1.0
// n0 -------------- n1
//    point-to-point
//

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("FirstScriptExample");

void recvNormal(Ptr<Socket> sock) {
  NS_LOG_DEBUG(Now().GetSeconds() << "s, Normal");
  Address org_src;
  Ptr<Packet> packet;
  while(packet = sock->RecvFrom(org_src)){
    InetSocketAddress inet_src = InetSocketAddress::ConvertFrom(org_src);
    NS_LOG_DEBUG("received a normal packet from " << inet_src.GetIpv4() << " "
                                                  << inet_src.GetPort());
    Ptr<Packet> pck = Create<Packet>();
    sock->SendTo(pck,0,org_src);
  }
  Simulator::Schedule(Seconds(1.0), &recvNormal, sock);
}

void ThroughputMonitor (FlowMonitorHelper *flowMonitorHelper, Ptr<FlowMonitor> flowMonitor){
  NS_LOG_INFO(Now());
  flowMonitor->CheckForLostPackets();
  std::map<FlowId, FlowMonitor::FlowStats> flowStats = flowMonitor->GetFlowStats();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowMonitorHelper->GetClassifier());
  for (auto item:flowStats) {
    // FiveTuple五元组是：(source-ip, destination-ip, protocol, source-port, destination-port)
    auto tmp = classifier->FindFlow (item.first);
    NS_LOG_INFO(tmp.sourceAddress << " " <<
                tmp.sourcePort << " " <<
                tmp.destinationAddress << " " <<
                tmp.destinationPort);
  }
  Simulator::Schedule(Seconds(1.), &ThroughputMonitor, flowMonitorHelper, flowMonitor);
}

int main(int argc, char *argv[]) {
  CommandLine cmd(__FILE__);
  cmd.Parse(argc, argv);

  Time::SetResolution(Time::NS);
  LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpSocketImpl", LOG_LEVEL_ALL);
  LogComponentEnable("FirstScriptExample", LOG_LEVEL_ALL);

  NodeContainer nodes;
  nodes.Create(2);


  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));

  NetDeviceContainer devices;
  devices = pointToPoint.Install(nodes);

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer interfaces = address.Assign(devices);

  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowMonitorHelper;
  flowMonitor = flowMonitorHelper.Install(nodes);

  // Config::SetDefault("ns3::UdpSocket::RcvBufSize", UintegerValue(1<<10));
  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  Ptr<Socket> recv = Socket::CreateSocket(nodes.Get(1), tid);
  recv->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9));
  // recv->SetRecvCallback(MakeCallback(&recvNormalCallback));
  recv->SetAttribute("RcvBufSize", UintegerValue(1<<11));
  Simulator::Schedule(Seconds(1e-9), &recvNormal, recv);

  UdpEchoClientHelper echoClient(interfaces.GetAddress(1), 9);
  echoClient.SetAttribute("MaxPackets", UintegerValue(10));
  echoClient.SetAttribute("Interval", TimeValue(Seconds(0.4)));
  echoClient.SetAttribute("PacketSize", UintegerValue(1024));

  ApplicationContainer clientApps = echoClient.Install(nodes.Get(0));
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(10.0));
  

  // Simulator::Schedule(Seconds(1.0), ThroughputMonitor, &flowMonitorHelper, flowMonitor);
  Simulator::Stop(Seconds(10.));
  Simulator::Run();
  std::stringstream stmp;
  stmp << "./first.flowmon";
  flowMonitor->SerializeToXmlFile (stmp.str ().c_str (), true, true);
  Simulator::Destroy();
  return 0;
}
