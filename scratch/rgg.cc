#include <iostream>
#include <string>
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/wifi-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AdHoctask");

int main(int argc, char *argv[]) {
  Time::SetResolution(Time::NS);

  LogComponentEnable("AdHoctask", LOG_LEVEL_INFO);

  LogComponentEnable("PacketSink", LOG_LEVEL_ALL);

  uint32_t nAdHoc = 50;  // 50个节点

  CommandLine cmd;
  cmd.AddValue("nAdHoc", "Number of wifi adDevices",
               nAdHoc);  //可以在命令行修改的参数
  cmd.Parse(argc, argv);
  //建立无线自组网节点（50个）

  NodeContainer adHocNodes;
  adHocNodes.Create(nAdHoc);

  //建立wifi网络相关设备，并在channel部分的propagation=loss=model设置为Range-propagation-loss-model
  //这就可以对其下的属性maxrange进行修改，实际上就是节点的通讯半径
  WifiHelper wifi;
  YansWifiPhyHelper wifiPhy;
  wifiPhy.SetErrorRateModel("ns3::NistErrorRateModel");
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
  //特别的，我们在这里修改了信道内的两个属性，将propagation-loss-module设置为Range-propagation-loss-model，并将其下一个属性maxrange设置成50，可以理解为最大通讯半径
  wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange",
                                 DoubleValue(50.0));
  wifiPhy.SetChannel(wifiChannel.Create());
  WifiMacHelper wifiMac;
  wifiMac.SetType("ns3::AdhocWifiMac");  //注意是adhoc类型

  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
                               StringValue("OfdmRate6Mbps"), "RtsCtsThreshold",
                               UintegerValue(0));
  NetDeviceContainer adHocDevices = wifi.Install(wifiPhy, wifiMac, adHocNodes);
  //为节点随机分配位置进而构成随机几何模型，这里指的是在以（100，100）为心，300为半径的圆里随机初始化位置

  MobilityHelper mobility;
  mobility.SetPositionAllocator(
      "ns3::RandomDiscPositionAllocator", "X", StringValue("100.0"),
      "Y", StringValue("100.0"),
      "Rho", StringValue("ns3::UniformRandomVariable[Min=0|Max=300]"));
  //并且固定每一个节点
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(adHocNodes);
  //之后在节点上安装协议栈，以及为节点分配IP地址

  InternetStackHelper stack;
  stack.Install(adHocNodes);

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer AdHocIp;
  AdHocIp = address.Assign(adHocDevices);

  Ipv4GlobalRoutingHelper::PopulateRoutingTables();

  Simulator::Stop(Seconds(500.0));
  Simulator::Run();
  Simulator::Destroy();

  return 0;
}
