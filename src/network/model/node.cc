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
    m_attacker_thrsh (2),
    m_attacker_validtime (Seconds(0.2))
{
  NS_LOG_FUNCTION (this);
  Construct ();
}

Node::Node(uint32_t sid, uint32_t flag, Time flagtime,
           Time sustime,  double prob, uint32_t thrsh, Time attacktime)
  : m_id (0),
    m_sid (sid),
    m_flag (flag),
    m_flag_validtime (flagtime),
    m_suspicious_validtime (sustime),
    m_attacker_prob (prob),
    m_attacker_thrsh (thrsh),
    m_attacker_validtime (attacktime)
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

void Node::SetFlag(uint32_t flag) {
  NS_LOG_FUNCTION(this);
  m_flag = flag;
  m_flag_settime = Now();
}

uint32_t Node::GetFlag(void){
  NS_LOG_FUNCTION(this);
  if (m_flag != kNodeFlag::FLAG_NORMAL && 
      Now() - GetFlagSetTime() > GetFlagValidTime()) {
    NS_LOG_INFO("node become normal because of exceed valid time.");
    SetFlag(kNodeFlag::FLAG_NORMAL);
    m_suspects.clear();
    m_attackers.clear();
  }
  return m_flag;
}

Time Node::GetFlagSetTime(void) const {
  NS_LOG_FUNCTION(this);
  return m_flag_settime;
}

Time Node::GetFlagValidTime(void) const {
  NS_LOG_FUNCTION(this);
  return m_flag_validtime;
}

void Node::SetFlagValidTime(Time validtime) {
  NS_LOG_FUNCTION(this);
  m_flag_validtime = validtime;
}

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

void Node::SetSuspiciousValidTime(Time validtime) {
  NS_LOG_FUNCTION(this);
  m_suspicious_validtime = validtime;
}

Time Node::GetSuspiciousValidTime() const {
  NS_LOG_FUNCTION(this);
  return m_suspicious_validtime;
}

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

uint32_t Node::GetAttackerThrsh(void) {
  NS_LOG_FUNCTION(this);
  return m_attacker_thrsh;
}

void Node::SetAttackerThrsh(uint32_t thrsh) {
  NS_LOG_FUNCTION(this);
  m_attacker_thrsh = thrsh;
}

bool Node::IsAttacker(std::pair<Ipv4Address, Ipv4Address> src2dst) {
  NS_LOG_FUNCTION(this);
  if (m_attackers.find(src2dst) == m_attackers.end()) return false;
  Time tim = m_attackers[src2dst];
  if (Now() - tim > m_suspicious_validtime) {
    // 超过时间，移除
    m_attackers.erase(src2dst);
    return false;
  }
  return true;
}

bool Node::AddAttacker(std::pair<Ipv4Address, Ipv4Address> src2dst, Time nowtime) {
  NS_LOG_FUNCTION(this);
  if (m_suspects.find(src2dst) == m_suspects.end())
    return false;
  if (nowtime == Seconds(0)) nowtime = Now();
  if (GetFlag() == kNodeFlag::FLAG_DEFEND) {
    m_suspects[src2dst].second++;
    if (m_suspects[src2dst].second > m_attacker_thrsh){
      m_suspects[src2dst].second = 0;
      m_attackers[src2dst] = nowtime;
      return true;
    }
  } else if (GetFlag() == kNodeFlag::FLAG_PROBE) {
    if (1.*rand() / RAND_MAX < m_attacker_prob){
      m_attackers[src2dst] = nowtime;
      return true;
    }
  }
  return false;
}

void Node::SetAttackerValidTime(Time validtime) {
  NS_LOG_FUNCTION(this);
  m_attacker_validtime = validtime;
}

Time Node::GetAttackerValidTime() const {
  NS_LOG_FUNCTION(this);
  return m_attacker_validtime;
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
