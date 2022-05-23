#include <bits/stdc++.h>

#include <cmath>
#include <iostream>

#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/inet-socket-address.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/on-off-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/v4traceroute-helper.h"
#include "ns3/v4traceroute.h"
#include "ns3/wifi-module.h"
#include "ns3/nix-vector-helper.h"

using namespace ns3;

class CrossFire {
 public:
  CrossFire();
  bool Configure(int argc, char **argv);
  void Run();
  void Report(std::ostream &os);

 private:
  uint32_t size;
  double step;
  double totalTime;
  bool pcap;
  bool printRoutes;
  NodeContainer nodes;
  NetDeviceContainer devices;
  Ipv4InterfaceContainer interfaces;
  uint32_t packetSize;
  uint32_t revPort;
  double RGGradius;

 private:
  /// Create the nodes
  void CreateNodes();
  /// Create the devices
  void CreateDevices();
  /// Create the network
  void InstallInternetStack();
  /// Create the simulation applications
  void InstallApplications();

  void BuildCrossFireAttack(Ptr<Node> attacker, Ipv4Address serverIP);
  double intervalTraceRouteCheck;
  uint32_t numTraceRouteCheck;
  void TraceRoutePathCheck(Ptr<Node> attacker, Ptr<V4TraceRoute> trace);
};
void RecvCallback(Ptr<Socket> sock);

int main(int argc, char **argv) {
  CrossFire test;
  if (!test.Configure(argc, argv)) {
    NS_FATAL_ERROR("Configuration failed. Aborted.");
  }

  test.Run();
  test.Report(std::cout);
  return 0;
}

//-----------------------------------------------------------------------------
CrossFire::CrossFire()
    : size(25), step(50), totalTime(100), pcap(false), printRoutes(false) {
  packetSize = 1024;
  revPort = 10086;
  intervalTraceRouteCheck = 0.1;
  RGGradius = 0.6;
  // RGGradius = sqrt(log(size) / (acos(-1.0) * size));
  numTraceRouteCheck = 10;
}

bool CrossFire::Configure(int argc, char **argv) {
  // Enable AODV logs by default. Comment this if too noisy
  // LogComponentEnable("AodvRoutingProtocol", LOG_LEVEL_ALL);
  // LogComponentEnable("V4TraceRoute", LOG_LEVEL_ALL);
  // LogComponentEnable("OnOffApplication", LOG_LEVEL_ALL);

  SeedManager::SetSeed(12345);
  CommandLine cmd(__FILE__);

  cmd.AddValue("pcap", "Write PCAP traces.", pcap);
  cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
  cmd.AddValue("size", "Number of nodes.", size);
  cmd.AddValue("time", "Simulation time, s.", totalTime);
  cmd.AddValue("step", "Grid step, m", step);

  cmd.Parse(argc, argv);

  return true;
}

void CrossFire::Run() {
  CreateNodes();

  CreateDevices();

  InstallInternetStack();

  InstallApplications();

  std::cout << "Starting simulation for " << totalTime << " s ...\n";

  Simulator::Stop(Seconds(totalTime));
  Simulator::Run();
  Simulator::Destroy();
}

void CrossFire::Report(std::ostream &) {}

void CrossFire::CreateNodes() {
  std::cout << "Creating " << (unsigned)size << " nodes " << step
            << " m apart.\n";
  nodes.Create(size);
  // Name nodes
  for (uint32_t i = 0; i < size; ++i) {
    std::ostringstream os;
    os << "node-" << i;
    Names::Add(os.str(), nodes.Get(i));
  }
  // Create static grid
  MobilityHelper mobility;
  Ptr<RandomRectanglePositionAllocator> randomPosition =
      CreateObject<RandomRectanglePositionAllocator>();
  randomPosition->SetAttribute(
      "X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
  randomPosition->SetAttribute(
      "Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
  mobility.SetPositionAllocator(randomPosition);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes);
}

void CrossFire::CreateDevices() {
  // 生成RGG图
  for (uint32_t i = 0; i<nodes.GetN(); i++)
  for (uint32_t j = i + 1;j<nodes.GetN(); j++) {
    auto uP = nodes.Get(i)->GetObject<MobilityModel>()->GetPosition();
    auto vP = nodes.Get(j)->GetObject<MobilityModel>()->GetPosition();
    double dis = (uP-vP).GetLength();
    if (dis < 1000 * RGGradius){
      PointToPointHelper pointToPoint;
      pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps")); //这里可以控制速率
      pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));
      auto d1 = pointToPoint.Install (nodes.Get(i), nodes.Get(j));
      devices.Add(d1);
      // NS_LOG_UNCOND(i<<" "<<j);
    }
  }
  // WifiMacHelper wifiMac;
  // wifiMac.SetType("ns3::AdhocWifiMac");
  // YansWifiPhyHelper wifiPhy;
  // YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
  // wifiPhy.SetChannel(wifiChannel.Create());
  // WifiHelper wifi;
  // wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
  //                              StringValue("OfdmRate6Mbps"), "RtsCtsThreshold",
  //                              UintegerValue(0));
  // devices = wifi.Install(wifiPhy, wifiMac, nodes);

  // if (pcap) {
  //   wifiPhy.EnablePcapAll(std::string("aodv"));
  // }
}

void CrossFire::InstallInternetStack() {
  InternetStackHelper stack;
  // AodvHelper aodv;
  // you can configure AODV attributes here using aodv.Set(name, value)
  // stack.SetRoutingHelper(aodv);  // has effect on the next Install ()
  Ipv4NixVectorHelper nixRouting;
  stack.SetRoutingHelper (nixRouting);
  stack.Install(nodes);
  Ipv4AddressHelper address;
  address.SetBase("10.0.0.0", "255.255.0.0");
  interfaces = address.Assign(devices);

  if (printRoutes) {
    Ptr<OutputStreamWrapper> routingStream =
        Create<OutputStreamWrapper>("aodv.routes", std::ios::out);
    // aodv.PrintRoutingTableAllAt(Seconds(8), routingStream);
  }
}

void CrossFire::InstallApplications() {
  V4TraceRouteHelper traceroute(Ipv4Address("10.0.0.2"));
  ApplicationContainer p = traceroute.Install(nodes.Get (0));
  p.Start(Seconds(totalTime));

  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  for (uint32_t i = 0; i < nodes.GetN(); i++) {
    Ptr<Socket> recvSocket = Socket::CreateSocket(nodes.Get(i), tid);
    recvSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), revPort));
    recvSocket->SetRecvCallback(MakeCallback(&RecvCallback));
  }

  Ptr<Node> server = nodes.Get(size - 1);
  Ptr<Ipv4> ipv4 = server->GetObject<Ipv4>();
  Ipv4Address serverIP = ipv4->GetAddress(1, 0).GetLocal();
  Simulator::Schedule(Seconds(3), &CrossFire::BuildCrossFireAttack, this, nodes.Get(0), serverIP);
}

void CrossFire::BuildCrossFireAttack(Ptr<Node> attacker, Ipv4Address serverIP) {
  Ptr<V4TraceRoute> trace =
      attacker->GetApplication(0)->GetObject<V4TraceRoute>();
  trace->SetAttribute("Remote", Ipv4AddressValue(serverIP));
  trace->ReStartApplication();
  Simulator::ScheduleNow(&CrossFire::TraceRoutePathCheck, this, attacker, trace);
}

void CrossFire::TraceRoutePathCheck(Ptr<Node> attacker,
                                    Ptr<V4TraceRoute> trace) {
  if (trace->GetFindFlag() == 0)
    Simulator::Schedule(Seconds(intervalTraceRouteCheck),
                        &CrossFire::TraceRoutePathCheck, this, attacker, trace);
  else if (trace->GetFindFlag() == 1) {
    auto V = trace->GetInetSocketAddressVec();
    if (V.size() > 2) {
      Ipv4Address targeIP = V[V.size() - 3].GetIpv4();
      NS_LOG_UNCOND("target: " << targeIP);
      // attack
      OnOffHelper onOffAttack(
          "ns3::UdpSocketFactory",
          Address(InetSocketAddress(targeIP, revPort)));
          onOffAttack.SetConstantRate(DataRate((packetSize << 3) * 7), packetSize);
          onOffAttack.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=2]"));
          onOffAttack.SetAttribute("OffTime", StringValue("ns3::UniformRandomVariable[Min=0|Max=0.1]"));
          ApplicationContainer appAttacker = onOffAttack.Install(attacker);
          appAttacker.Start(Now() + Seconds(1e-3 * rand() / RAND_MAX));
    }
  }
}

void RecvCallback(Ptr<Socket> sock){
  Address sourceAddress;
  Ptr<Packet> packet = sock->RecvFrom(sourceAddress);
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom(sourceAddress);
  Ipv4Address sender = inetSourceAddr.GetIpv4();
  NS_LOG_UNCOND(Now() << " " << sender << " " << sock->GetNode()->GetObject<Ipv4>()->GetAddress(1, 0).GetLocal());
}