/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 Magister Solutions
 *
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
 *
 * Author: Lauri Sormunen <lauri.sormunen@magister.fi>
 */

/*
 Network Topology
 n0-------------n1
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("RandomOnoffExample");

int main(int argc, char *argv[]) {
  LogComponentEnable("RandomOnOffApplication", LOG_LEVEL_ALL);
  CommandLine cmd;
  cmd.Parse(argc,argv);

  NodeContainer nodes;
  nodes.Create(2);

  PointToPointHelper pointToPointHelper;
  pointToPointHelper.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
  pointToPointHelper.SetChannelAttribute("Delay", StringValue("1ms"));

  NetDeviceContainer devices;
  devices = pointToPointHelper.Install(nodes);

  InternetStackHelper inetStackHelper;
  Ipv4GlobalRoutingHelper::PopulateRoutingTables();
  inetStackHelper.Install(nodes);

  Ipv4AddressHelper addressHelper;
  addressHelper.SetBase("10.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer interfaces = addressHelper.Assign(devices);

  uint32_t port = 2333;

  PacketSinkHelper packetSinkHelper(
    "ns3::TcpSocketFactory",
    Address(InetSocketAddress(
      Ipv4Address::GetAny(), port
    ))
  );
  ApplicationContainer serverApp = packetSinkHelper.Install(nodes.Get(1));
  serverApp.Start(Seconds(0.0));
  serverApp.Stop(Seconds(100.0));

  RandomOnOffHelper randomOnOffHelper(
    "ns3::TcpSocketFactory",
    Address(InetSocketAddress(
      interfaces.GetAddress(1), port
    ))
  );
  randomOnOffHelper.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=100]"));
  randomOnOffHelper.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
  randomOnOffHelper.SetAttribute("Interval", StringValue("ns3::ExponentialRandomVariable[Mean=0.5|Bound=0.0]"));
  randomOnOffHelper.SetAttribute("PacketSize", StringValue("ns3::UniformRandomVariable[Min=0|Max=2048]"));

  ApplicationContainer sendApps;
  sendApps.Add(randomOnOffHelper.Install(nodes.Get(0)));
  sendApps.Start(Seconds(0.0));
  sendApps.Stop(Seconds(100.0));
  AnimationInterface anim("random-onoff-example.xml");
  AnimationInterface::SetConstantPosition (nodes.Get(0),12,12);
  AnimationInterface::SetConstantPosition (nodes.Get(1),24,24);
  anim.EnablePacketMetadata();


  Simulator::Run();
  Simulator::Destroy();
  return 0;
}
