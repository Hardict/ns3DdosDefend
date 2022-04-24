/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2006 Georgia Tech Research Corporation, INRIA
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
 * Authors: George F. Riley<riley@ece.gatech.edu>
 *          Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
 
#include "node.h"
#include "node-list.h"
#include "net-device.h"
#include "application.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/object-vector.h"
#include "ns3/uinteger.h"
#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/global-value.h"
#include "ns3/boolean.h"
#include <algorithm>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Node");

NS_OBJECT_ENSURE_REGISTERED (Node);

/**
 * \relates Node
 * \anchor GlobalValueChecksumEnabled
 * \brief A global switch to enable all checksums for all protocols.
 */
static GlobalValue g_checksumEnabled  = GlobalValue ("ChecksumEnabled",
                                                     "A global switch to enable all checksums for all protocols",
                                                     BooleanValue (false),
                                                     MakeBooleanChecker ());

TypeId 
Node::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::Node")
    .SetParent<Object> ()
    .SetGroupName("Network")
    .AddConstructor<Node> ()
    .AddAttribute ("DeviceList", "The list of devices associated to this Node.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&Node::m_devices),
                   MakeObjectVectorChecker<NetDevice> ())
    .AddAttribute ("ApplicationList", "The list of applications associated to this Node.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&Node::m_applications),
                   MakeObjectVectorChecker<Application> ())
    .AddAttribute ("Id", "The id (unique integer) of this Node.",
                   TypeId::ATTR_GET, // allow only getting it.
                   UintegerValue (0),
                   MakeUintegerAccessor (&Node::m_id),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("SystemId", "The systemId of this node: a unique integer used for parallel simulations.",
                   TypeId::ATTR_GET | TypeId::ATTR_SET,
                   UintegerValue (0),
                   MakeUintegerAccessor (&Node::m_sid),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NodeTag", "The behaviour of this: normal, probe or defend.",
                   TypeId::ATTR_GET | TypeId::ATTR_SET,
                   UintegerValue(0),
                   MakeUintegerAccessor (&Node::m_flag),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("TagValidTime", "The valid time of this node, update in user code.",
                   TypeId::ATTR_GET | TypeId::ATTR_SET,
                   TimeValue(Seconds(0.25)),
                   MakeTimeAccessor (&Node::m_flag_validtime),
                   MakeTimeChecker ())
    .AddAttribute ("SuspiciousValidTime", "The valid time of the suspicious set.",
                   TypeId::ATTR_GET | TypeId::ATTR_SET,
                   TimeValue(Seconds(0.2)),
                   MakeTimeAccessor (&Node::m_suspicious_validtime),
                   MakeTimeChecker ())
  ;
  return tid;
}

Node::Node()
  : m_id (0),
    m_sid (0),
    m_flag (0),
    m_flag_validtime (Seconds(0.25)),
    m_suspicious_validtime (Seconds(0.2)),
    m_attacker_prob (1.),
    m_probe_attacker_thrsh (1),
    m_probe_resend_thrsh (10),
    m_defend_attacker_thrsh (2),
    m_attacker_validtime (Seconds(0.2)),
    m_changeEnergyArgs (MakeNullCallback<void, Ptr<Node>>())
{
  NS_LOG_FUNCTION (this);
  Construct ();
}

Node::Node(uint32_t sid, uint32_t flag, Time flagtime,
           Time sustime,  double prob, uint32_t probe_thrsh,
           uint32_t resend_thrsh, uint32_t defend_thrsh, Time attacktime)
  : m_id (0),
    m_sid (sid),
    m_flag (flag),
    m_flag_validtime (flagtime),
    m_suspicious_validtime (sustime),
    m_attacker_prob (prob),
    m_probe_attacker_thrsh (probe_thrsh),
    m_probe_resend_thrsh (resend_thrsh),
    m_defend_attacker_thrsh (defend_thrsh),
    m_attacker_validtime (attacktime),
    m_changeEnergyArgs (MakeNullCallback<void, Ptr<Node>>())
{ 
  NS_LOG_FUNCTION (this << sid);
  Construct ();
}

void
Node::Construct (void)
{
  NS_LOG_FUNCTION (this);
  m_id = NodeList::Add (this);
}

Node::~Node ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t
Node::GetId (void) const
{
  NS_LOG_FUNCTION (this);
  return m_id;
}

//====Flag====
void Node::SetFlag(uint32_t flag) {
  NS_LOG_FUNCTION(this);
  m_flag = flag;
  m_flag_settime = Now();
  if (!m_changeEnergyArgs.IsNull()){
    m_changeEnergyArgs(this);
  }
}

uint32_t Node::GetFlag(void){
  NS_LOG_FUNCTION(this);
  if (m_flag != kNodeFlag::FLAG_NORMAL && 
      Now() - GetFlagSetTime() > GetFlagValidTime()) {
    NS_LOG_INFO("node become normal because of exceed valid time.");
    SetFlag(kNodeFlag::FLAG_NORMAL);
    std::map<uint32_t, Time>().swap(m_received_pids);
    std::set<std::pair<uint32_t, std::pair<Ipv4Address, Ipv4Address>>>().swap(m_received_defendinfos);
    std::map<std::pair<Ipv4Address, Ipv4Address>, std::pair<Time, uint32_t>>().swap(m_suspects);
    for (auto item : m_attackers)
      AddSuspect(item.first);
    std::map<std::pair<Ipv4Address, Ipv4Address>, std::pair<Time, uint32_t>>().swap(m_attackers);
    // m_received_pids.clear();
    // m_received_defendinfos.clear();
    // m_suspects.clear();
    // m_attackers.clear();
  }
  return m_flag;
}

Time Node::GetFlagSetTime(void){
  NS_LOG_FUNCTION(this);
  return m_flag_settime;
}

Time Node::GetFlagValidTime(void){
  NS_LOG_FUNCTION(this);
  return m_flag_validtime;
}

void Node::SetFlagValidTime(Time validtime) {
  NS_LOG_FUNCTION(this);
  m_flag_validtime = validtime;
}

bool Node::IsReceivedPid(uint32_t pid) {
  NS_LOG_FUNCTION(this);
  if (m_received_pids.find(pid) == m_received_pids.end()) return false;
  if (Now() - m_received_pids[pid] > m_flag_validtime){
    m_received_pids.erase(pid);
    return false;
  }
  return true;
}

void Node::AddReceivedPid(uint32_t pid) {
  NS_LOG_FUNCTION(this);
  m_received_pids[pid] = Now();
}

bool Node::IsReceivedDefendInfo(uint32_t nodeid, std::pair<Ipv4Address, Ipv4Address> src2dst) {
  NS_LOG_FUNCTION(this);
  auto pir = std::make_pair(nodeid, src2dst);
  if (m_received_defendinfos.find(pir) == m_received_defendinfos.end()) return false;
  return true;
}

void Node::AddReceivedDefendInfo(uint32_t nodeid, std::pair<Ipv4Address, Ipv4Address> src2dst) {
  NS_LOG_FUNCTION(this);
  auto pir = std::make_pair(nodeid, src2dst);
  m_received_defendinfos.insert(pir);
}

//====Parameter Setting====
double Node::GetAttackerProb(void) {
  NS_LOG_FUNCTION(this);
  return m_attacker_prob;
}

void Node::SetAttackerProb(double prob) {
  NS_LOG_FUNCTION(this);
  if(prob > 1.){
    NS_LOG_INFO("probability > 1, will set to 1");
    prob = 1.;
  }
  if(prob < 0){
    NS_LOG_INFO("probability < 0, will set to 0");
    prob = 0;
  }
  m_attacker_prob = prob;
}

uint32_t Node::GetProbeAttackerThrsh(void) {
  NS_LOG_FUNCTION(this);
  return m_probe_attacker_thrsh;
}

void Node::SetProbeAttackerThrsh(uint32_t thrsh) {
  NS_LOG_FUNCTION(this);
  m_probe_attacker_thrsh = thrsh;
}

uint32_t Node::GetProbeResendThrsh(void) {
  NS_LOG_FUNCTION(this);
  return m_probe_resend_thrsh;
}

void Node::SetProbeResendThrsh(uint32_t thrsh) {
  NS_LOG_FUNCTION(this);
  m_probe_resend_thrsh = thrsh;
}

uint32_t Node::GetDefendAttackerThrsh(void) {
  NS_LOG_FUNCTION(this);
  return m_defend_attacker_thrsh;
}

void Node::SetDefendAttackerThrsh(uint32_t thrsh) {
  NS_LOG_FUNCTION(this);
  m_defend_attacker_thrsh = thrsh;
}

Time Node::GetSuspiciousValidTime(){
  NS_LOG_FUNCTION(this);
  return m_suspicious_validtime;
}

void Node::SetSuspiciousValidTime(Time validtime) {
  NS_LOG_FUNCTION(this);
  m_suspicious_validtime = validtime;
}

void Node::SetAttackerValidTime(Time validtime) {
  NS_LOG_FUNCTION(this);
  m_attacker_validtime = validtime;
}

Time Node::GetAttackerValidTime(){
  NS_LOG_FUNCTION(this);
  return m_attacker_validtime;
}

uint32_t Node::QueryDropN(std::pair<Ipv4Address, Ipv4Address> src2dst){
  NS_LOG_FUNCTION(this);
  return m_countdrops[src2dst].first;
}

bool Node::CountDrop(std::pair<Ipv4Address, Ipv4Address> src2dst) {
  NS_LOG_FUNCTION(this);
  m_countdrops[src2dst].first++;
  if (GetFlag() == kNodeFlag::FLAG_PROBE) {
    m_attackers[src2dst].second++;
    uint32_t k = m_countdrops[src2dst].second;
    if (k > 4) k = 4;
    k = 1 << k;
    if (m_attackers[src2dst].second >= m_probe_resend_thrsh * k){
      m_attackers[src2dst].second = 0;
      m_countdrops[src2dst].second++;
      return true;
    }
  }
  return false;
}

//====Tabel Maintenance====
bool Node::IsSuspect(Ipv4Address src, Ipv4Address dst) {
  NS_LOG_FUNCTION(this);
  return IsSuspect(std::make_pair(src, dst));
}

bool Node::IsSuspect(std::pair<Ipv4Address, Ipv4Address> src2dst) {
  NS_LOG_FUNCTION(this);
  if (m_suspects.find(src2dst) == m_suspects.end()) return false;
  Time tim = m_suspects[src2dst].first;
  if (Now() - tim > m_suspicious_validtime) {
    // 超过时间，不再可疑
    m_suspects.erase(src2dst);
    return false;
  }
  return true;
}

void Node::AddSuspect(Ipv4Address src, Ipv4Address dst, Time nowtime) {
  NS_LOG_FUNCTION(this);
  if (nowtime == Seconds(0)) nowtime = Now();
  m_suspects[std::make_pair(src, dst)].first = nowtime;
}

void Node::AddSuspect(std::pair<Ipv4Address, Ipv4Address> src2dst, Time nowtime) {
  NS_LOG_FUNCTION(this);
  if (nowtime == Seconds(0)) nowtime = Now();
  m_suspects[src2dst].first = nowtime;
}

bool Node::IsAttacker(std::pair<Ipv4Address, Ipv4Address> src2dst) {
  NS_LOG_FUNCTION(this);
  if (m_attackers.find(src2dst) == m_attackers.end()) return false;
  Time tim = m_attackers[src2dst].first;
  if (Now() - tim > m_suspicious_validtime) {
    // 超过时间，移除
    m_attackers.erase(src2dst);
    std::vector<std::pair<uint32_t, std::pair<Ipv4Address, Ipv4Address>>> V;
    for (auto item: m_received_defendinfos)
      if (item.second == src2dst)
        V.push_back(item);
    for (auto item:V) m_received_defendinfos.erase(item);
    // 下面两种都会内存泄漏
    // auto new_end = std::remove_if(m_received_defendinfos.begin (), m_received_defendinfos.end (),
    //                           [&](const std::pair<uint32_t, std::pair<Ipv4Address, Ipv4Address>>& a) {
    //                             return a.second == src2dst;
    //                           });
    // m_received_defendinfos.erase (new_end, m_received_defendinfos.end ());
    // for (auto item: m_received_defendinfos)
    //   if (item.second == src2dst)
    //     m_received_defendinfos.erase(item);
    return false;
  }
  return true;
}

bool Node::AddAttacker(std::pair<Ipv4Address, Ipv4Address> src2dst, Time nowtime) {
  NS_LOG_FUNCTION(this);
  if (m_suspects.find(src2dst) == m_suspects.end())
    return false;
  if (nowtime == Seconds(0)) nowtime = Now();
  m_suspects[src2dst].second++;
  if (GetFlag() == kNodeFlag::FLAG_DEFEND) {
    if (m_suspects[src2dst].second >= m_defend_attacker_thrsh){
      m_suspects[src2dst].second = 0;
      m_attackers[src2dst].first = nowtime;
      m_attackers[src2dst].second = 0;
      return true;
    }
  } else if (GetFlag() == kNodeFlag::FLAG_PROBE) {
    if (m_suspects[src2dst].second >= m_probe_attacker_thrsh &&
        1.*rand() / RAND_MAX < m_attacker_prob){
      m_attackers[src2dst].first = nowtime;
      m_attackers[src2dst].second = 0;
      return true;
    }
  }
  return false;
}

void Node::SetChangeEnergyArgsCallback(Callback<void, Ptr<Node>> changeEnergyArgs){
  NS_LOG_FUNCTION(this);
  m_changeEnergyArgs = changeEnergyArgs;
}

Time
Node::GetLocalTime (void) const
{
  NS_LOG_FUNCTION (this);
  return Simulator::Now ();
}

uint32_t
Node::GetSystemId (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sid;
}

uint32_t
Node::AddDevice (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  uint32_t index = m_devices.size ();
  m_devices.push_back (device);
  device->SetNode (this);
  device->SetIfIndex (index);
  device->SetReceiveCallback (MakeCallback (&Node::NonPromiscReceiveFromDevice, this));
  Simulator::ScheduleWithContext (GetId (), Seconds (0.0), 
                                  &NetDevice::Initialize, device);
  NotifyDeviceAdded (device);
  return index;
}
Ptr<NetDevice>
Node::GetDevice (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  NS_ASSERT_MSG (index < m_devices.size (), "Device index " << index <<
                 " is out of range (only have " << m_devices.size () << " devices).");
  return m_devices[index];
}
uint32_t 
Node::GetNDevices (void) const
{
  NS_LOG_FUNCTION (this);
  return m_devices.size ();
}

uint32_t 
Node::AddApplication (Ptr<Application> application)
{
  NS_LOG_FUNCTION (this << application);
  uint32_t index = m_applications.size ();
  m_applications.push_back (application);
  application->SetNode (this);
  Simulator::ScheduleWithContext (GetId (), Seconds (0.0), 
                                  &Application::Initialize, application);
  return index;
}
Ptr<Application> 
Node::GetApplication (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  NS_ASSERT_MSG (index < m_applications.size (), "Application index " << index <<
                 " is out of range (only have " << m_applications.size () << " applications).");
  return m_applications[index];
}
uint32_t 
Node::GetNApplications (void) const
{
  NS_LOG_FUNCTION (this);
  return m_applications.size ();
}

void 
Node::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_deviceAdditionListeners.clear ();
  m_handlers.clear ();
  for (std::vector<Ptr<NetDevice> >::iterator i = m_devices.begin ();
       i != m_devices.end (); i++)
    {
      Ptr<NetDevice> device = *i;
      device->Dispose ();
      *i = 0;
    }
  m_devices.clear ();
  for (std::vector<Ptr<Application> >::iterator i = m_applications.begin ();
       i != m_applications.end (); i++)
    {
      Ptr<Application> application = *i;
      application->Dispose ();
      *i = 0;
    }
  m_applications.clear ();
  Object::DoDispose ();
}
void 
Node::DoInitialize (void)
{
  NS_LOG_FUNCTION (this);
  for (std::vector<Ptr<NetDevice> >::iterator i = m_devices.begin ();
       i != m_devices.end (); i++)
    {
      Ptr<NetDevice> device = *i;
      device->Initialize ();
    }
  for (std::vector<Ptr<Application> >::iterator i = m_applications.begin ();
       i != m_applications.end (); i++)
    {
      Ptr<Application> application = *i;
      application->Initialize ();
    }

  Object::DoInitialize ();
}

void
Node::RegisterProtocolHandler (ProtocolHandler handler, 
                               uint16_t protocolType,
                               Ptr<NetDevice> device,
                               bool promiscuous)
{
  NS_LOG_FUNCTION (this << &handler << protocolType << device << promiscuous);
  struct Node::ProtocolHandlerEntry entry;
  entry.handler = handler;
  entry.protocol = protocolType;
  entry.device = device;
  entry.promiscuous = promiscuous;

  // On demand enable promiscuous mode in netdevices
  if (promiscuous)
    {
      if (device == 0)
        {
          for (std::vector<Ptr<NetDevice> >::iterator i = m_devices.begin ();
               i != m_devices.end (); i++)
            {
              Ptr<NetDevice> dev = *i;
              dev->SetPromiscReceiveCallback (MakeCallback (&Node::PromiscReceiveFromDevice, this));
            }
        }
      else
        {
          device->SetPromiscReceiveCallback (MakeCallback (&Node::PromiscReceiveFromDevice, this));
        }
    }

  m_handlers.push_back (entry);
}

void
Node::UnregisterProtocolHandler (ProtocolHandler handler)
{
  NS_LOG_FUNCTION (this << &handler);
  for (ProtocolHandlerList::iterator i = m_handlers.begin ();
       i != m_handlers.end (); i++)
    {
      if (i->handler.IsEqual (handler))
        {
          m_handlers.erase (i);
          break;
        }
    }
}

bool
Node::ChecksumEnabled (void)
{
  NS_LOG_FUNCTION_NOARGS ();
  BooleanValue val;
  g_checksumEnabled.GetValue (val);
  return val.Get ();
}

bool
Node::PromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                const Address &from, const Address &to, NetDevice::PacketType packetType)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from << &to << packetType);
  return ReceiveFromDevice (device, packet, protocol, from, to, packetType, true);
}

bool
Node::NonPromiscReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                                   const Address &from)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from);
  return ReceiveFromDevice (device, packet, protocol, from, device->GetAddress (), NetDevice::PacketType (0), false);
}

bool
Node::ReceiveFromDevice (Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol,
                         const Address &from, const Address &to, NetDevice::PacketType packetType, bool promiscuous)
{
  NS_LOG_FUNCTION (this << device << packet << protocol << &from << &to << packetType << promiscuous);
  NS_ASSERT_MSG (Simulator::GetContext () == GetId (), "Received packet with erroneous context ; " <<
                 "make sure the channels in use are correctly updating events context " <<
                 "when transferring events from one node to another.");
  NS_LOG_DEBUG ("Node " << GetId () << " ReceiveFromDevice:  dev "
                        << device->GetIfIndex () << " (type=" << device->GetInstanceTypeId ().GetName ()
                        << ") Packet UID " << packet->GetUid ());
  bool found = false;

  for (ProtocolHandlerList::iterator i = m_handlers.begin ();
       i != m_handlers.end (); i++)
    {
      if (i->device == 0 ||
          (i->device != 0 && i->device == device))
        {
          if (i->protocol == 0 || 
              i->protocol == protocol)
            {
              if (promiscuous == i->promiscuous)
                {
                  i->handler (device, packet, protocol, from, to, packetType);
                  found = true;
                }
            }
        }
    }
  return found;
}
void 
Node::RegisterDeviceAdditionListener (DeviceAdditionListener listener)
{
  NS_LOG_FUNCTION (this << &listener);
  m_deviceAdditionListeners.push_back (listener);
  // and, then, notify the new listener about all existing devices.
  for (std::vector<Ptr<NetDevice> >::const_iterator i = m_devices.begin ();
       i != m_devices.end (); ++i)
    {
      listener (*i);
    }
}
void 
Node::UnregisterDeviceAdditionListener (DeviceAdditionListener listener)
{
  NS_LOG_FUNCTION (this << &listener);
  for (DeviceAdditionListenerList::iterator i = m_deviceAdditionListeners.begin ();
       i != m_deviceAdditionListeners.end (); i++)
    {
      if ((*i).IsEqual (listener))
        {
          m_deviceAdditionListeners.erase (i);
          break;
         }
    }
}
 
void 
Node::NotifyDeviceAdded (Ptr<NetDevice> device)
{
  NS_LOG_FUNCTION (this << device);
  for (DeviceAdditionListenerList::iterator i = m_deviceAdditionListeners.begin ();
       i != m_deviceAdditionListeners.end (); i++)
    {
      (*i) (device);
    }  
}
 

} // namespace ns3
