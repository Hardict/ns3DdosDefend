/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
//
// Copyright (c) 2006 Georgia Tech Research Corporation
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation;
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// Author: George F. Riley<riley@ece.gatech.edu>
//

// ns3 - On/Off Data Source Application class
// George F. Riley, Georgia Tech, Spring 2007
// Adapted from ApplicationOnOff in GTNetS.

#include "random-onoff-application.h"

#include "ns3/address.h"
#include "ns3/boolean.h"
#include "ns3/data-rate.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/packet-socket-address.h"
#include "ns3/packet.h"
#include "ns3/pointer.h"
#include "ns3/random-variable-stream.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("RandomOnOffApplication");

NS_OBJECT_ENSURE_REGISTERED(RandomOnOffApplication);

TypeId RandomOnOffApplication::GetTypeId(void) {
  static TypeId tid =
      TypeId("ns3::RandomOnOffApplication")
          .SetParent<Application>()
          .SetGroupName("Applications")
          .AddConstructor<RandomOnOffApplication>()
          .AddAttribute("DataRate", "The data rate in on state.",
                        DataRateValue(DataRate("500kb/s")),
                        MakeDataRateAccessor(&RandomOnOffApplication::m_cbrRate),
                        MakeDataRateChecker())
          .AddAttribute(
              "PacketSize", "The size of packets sent in on state",
              StringValue("ns3::ConstantRandomVariable[Constant=512.0]"),
              MakePointerAccessor(&RandomOnOffApplication::m_pktSizeRng),
              MakePointerChecker<RandomVariableStream>())
          .AddAttribute(
              "Interval", "The value of sending interval.",
              StringValue("ns3::ConstantRandomVariable[Constant=1.0]"),
              MakePointerAccessor(&RandomOnOffApplication::m_intervalRng),
              MakePointerChecker<RandomVariableStream>())
          .AddAttribute("Remote", "The address of the destination",
                        AddressValue(),
                        MakeAddressAccessor(&RandomOnOffApplication::m_peer),
                        MakeAddressChecker())
          .AddAttribute("Local",
                        "The Address on which to bind the socket. If not set, "
                        "it is generated automatically.",
                        AddressValue(),
                        MakeAddressAccessor(&RandomOnOffApplication::m_local),
                        MakeAddressChecker())
          .AddAttribute(
              "OnTime",
              "A RandomVariableStream used to pick the duration of the 'On' "
              "state.",
              StringValue("ns3::ConstantRandomVariable[Constant=1.0]"),
              MakePointerAccessor(&RandomOnOffApplication::m_onTime),
              MakePointerChecker<RandomVariableStream>())
          .AddAttribute(
              "OffTime",
              "A RandomVariableStream used to pick the duration of the 'Off' "
              "state.",
              StringValue("ns3::ConstantRandomVariable[Constant=1.0]"),
              MakePointerAccessor(&RandomOnOffApplication::m_offTime),
              MakePointerChecker<RandomVariableStream>())
          .AddAttribute(
              "MaxBytes",
              "The total number of bytes to send. Once these bytes are sent, "
              "no packet is sent again, even in on state. The value zero means "
              "that there is no limit.",
              UintegerValue(0),
              MakeUintegerAccessor(&RandomOnOffApplication::m_maxBytes),
              MakeUintegerChecker<uint64_t>())
          .AddAttribute("Protocol",
                        "The type of protocol to use. This should be "
                        "a subclass of ns3::SocketFactory",
                        TypeIdValue(UdpSocketFactory::GetTypeId()),
                        MakeTypeIdAccessor(&RandomOnOffApplication::m_tid),
                        // This should check for SocketFactory as a parent
                        MakeTypeIdChecker())
          .AddAttribute(
              "EnableSeqTsSizeHeader",
              "Enable use of SeqTsSizeHeader for sequence number and timestamp",
              BooleanValue(false),
              MakeBooleanAccessor(&RandomOnOffApplication::m_enableSeqTsSizeHeader),
              MakeBooleanChecker())
          .AddTraceSource(
              "Tx", "A new packet is created and is sent",
              MakeTraceSourceAccessor(&RandomOnOffApplication::m_txTrace),
              "ns3::Packet::TracedCallback")
          .AddTraceSource("TxWithAddresses",
                          "A new packet is created and is sent",
                          MakeTraceSourceAccessor(
                              &RandomOnOffApplication::m_txTraceWithAddresses),
                          "ns3::Packet::TwoAddressTracedCallback")
          .AddTraceSource("TxWithSeqTsSize",
                          "A new packet is created with SeqTsSizeHeader",
                          MakeTraceSourceAccessor(
                              &RandomOnOffApplication::m_txTraceWithSeqTsSize),
                          "ns3::PacketSink::SeqTsSizeCallback");
  return tid;
}

RandomOnOffApplication::RandomOnOffApplication()
    : m_socket(0),
      m_connected(false),
      m_residualBits(0),
      m_lastStartTime(Seconds(0)),
      m_totBytes(0),
      m_unsentPacket(0) {
  NS_LOG_FUNCTION(this);
}

RandomOnOffApplication::~RandomOnOffApplication() { NS_LOG_FUNCTION(this); }

void RandomOnOffApplication::SetMaxBytes(uint64_t maxBytes) {
  NS_LOG_FUNCTION(this << maxBytes);
  m_maxBytes = maxBytes;
}

Ptr<Socket> RandomOnOffApplication::GetSocket(void) const {
  NS_LOG_FUNCTION(this);
  return m_socket;
}

int64_t RandomOnOffApplication::AssignStreams(int64_t stream) {
  NS_LOG_FUNCTION(this << stream);
  m_onTime->SetStream(stream);
  m_offTime->SetStream(stream + 1);
  m_intervalRng->SetStream(stream + 2);
  m_pktSizeRng->SetStream(stream + 3);
  return 4;
}

void RandomOnOffApplication::DoDispose(void) {
  NS_LOG_FUNCTION(this);

  CancelEvents();
  m_socket = 0;
  m_unsentPacket = 0;
  // chain up
  Application::DoDispose();
}

// Application Methods
// Called at time specified by Start
void RandomOnOffApplication::StartApplication() {
  NS_LOG_FUNCTION(this);

  // Create the socket if not already
  if (!m_socket) {
    m_socket = Socket::CreateSocket(GetNode(), m_tid);
    int ret = -1;

    if (!m_local.IsInvalid()) {
      NS_ABORT_MSG_IF((Inet6SocketAddress::IsMatchingType(m_peer) &&
                       InetSocketAddress::IsMatchingType(m_local)) ||
                          (InetSocketAddress::IsMatchingType(m_peer) &&
                           Inet6SocketAddress::IsMatchingType(m_local)),
                      "Incompatible peer and local address IP version");
      ret = m_socket->Bind(m_local);
    } else {
      if (Inet6SocketAddress::IsMatchingType(m_peer)) {
        ret = m_socket->Bind6();
      } else if (InetSocketAddress::IsMatchingType(m_peer) ||
                 PacketSocketAddress::IsMatchingType(m_peer)) {
        ret = m_socket->Bind();
      }
    }

    if (ret == -1) {
      NS_FATAL_ERROR("Failed to bind socket");
    }

    m_socket->Connect(m_peer);
    m_socket->SetAllowBroadcast(true);
    m_socket->ShutdownRecv();

    m_socket->SetConnectCallback(
        MakeCallback(&RandomOnOffApplication::ConnectionSucceeded, this),
        MakeCallback(&RandomOnOffApplication::ConnectionFailed, this));
  }
  m_cbrRateFailSafe = m_cbrRate;

  // Insure no pending event
  CancelEvents();
  // If we are not yet connected, there is nothing to do here
  // The ConnectionComplete upcall will start timers at that time
  // if (!m_connected) return;
  ScheduleStartEvent();
}

// Called at time specified by Stop
void RandomOnOffApplication::StopApplication() {
  NS_LOG_FUNCTION(this);

  CancelEvents();
  if (m_socket != 0) {
    m_socket->Close();
  } else {
    NS_LOG_WARN(
        "RandomOnOffApplication found null socket to close in StopApplication");
  }
}

void RandomOnOffApplication::CancelEvents() {
  NS_LOG_FUNCTION(this);

  if (m_sendEvent.IsRunning() &&
      m_cbrRateFailSafe == m_cbrRate) {  // Cancel the pending send packet event
    // Calculate residual bits since last packet sent
    Time delta(Simulator::Now() - m_lastStartTime);
    int64x64_t bits = delta.To(Time::S) * m_cbrRate.GetBitRate();
    m_residualBits += bits.GetHigh();
  }
  m_cbrRateFailSafe = m_cbrRate;
  Simulator::Cancel(m_sendEvent);
  Simulator::Cancel(m_startStopEvent);
  // Canceling events may cause discontinuity in sequence number if the
  // SeqTsSizeHeader is header, and m_unsentPacket is true
  if (m_unsentPacket) {
    NS_LOG_DEBUG("Discarding cached packet upon CancelEvents ()");
  }
  m_unsentPacket = 0;
}

// Event handlers
void RandomOnOffApplication::StartSending() {
  NS_LOG_FUNCTION(this);
  m_lastStartTime = Simulator::Now();
  ScheduleNextTx();  // Schedule the send packet event
  ScheduleStopEvent();
}

void RandomOnOffApplication::StopSending() {
  NS_LOG_FUNCTION(this);
  CancelEvents();

  ScheduleStartEvent();
}

// Private helpers
void RandomOnOffApplication::ScheduleNextTx() {
  NS_LOG_FUNCTION(this);

  m_pktSize = m_pktSizeRng->GetValue();

  if (m_maxBytes == 0 || m_totBytes < m_maxBytes) {
    NS_ABORT_MSG_IF(m_residualBits > m_pktSize * 8,
                    "Calculation to compute next send time will overflow");
    uint32_t bits = m_pktSize * 8 - m_residualBits;
    NS_LOG_LOGIC("bits = " << bits);
    double interval = m_intervalRng->GetValue();
    NS_LOG_LOGIC("interval = " << interval);
    // Time till next packet
    Time nextTime(
        Seconds(bits / static_cast<double>(m_cbrRate.GetBitRate()) + interval));
    NS_LOG_LOGIC("nextTime = " << nextTime.As(Time::S));
    m_sendEvent =
        Simulator::Schedule(nextTime, &RandomOnOffApplication::SendPacket, this);
  } else {  // All done, cancel any pending events
    StopApplication();
  }
}

// Schedules the event to start
// sending data (switch to the
// "On" state)
void RandomOnOffApplication::ScheduleStartEvent() {
  NS_LOG_FUNCTION(this);

  Time offInterval = Seconds(m_offTime->GetValue());
  NS_LOG_LOGIC("start at " << offInterval.As(Time::S));
  m_startStopEvent =
      Simulator::Schedule(offInterval, &RandomOnOffApplication::StartSending, this);
}

// Schedules the event to stop
// sending data (switch to "Off"
// state)
void RandomOnOffApplication::ScheduleStopEvent() {
  NS_LOG_FUNCTION(this);

  Time onInterval = Seconds(m_onTime->GetValue());
  NS_LOG_LOGIC("stop at " << onInterval.As(Time::S));
  m_startStopEvent =
      Simulator::Schedule(onInterval, &RandomOnOffApplication::StopSending, this);
}

void RandomOnOffApplication::SendPacket() {
  NS_LOG_FUNCTION(this);

  NS_ASSERT(m_sendEvent.IsExpired());

  Ptr<Packet> packet;
  if (m_unsentPacket) {
    packet = m_unsentPacket;
  } else if (m_enableSeqTsSizeHeader) {
    Address from, to;
    m_socket->GetSockName(from);
    m_socket->GetPeerName(to);
    SeqTsSizeHeader header;
    header.SetSeq(m_seq++);
    header.SetSize(m_pktSize);
    NS_ABORT_IF(m_pktSize < header.GetSerializedSize());
    packet = Create<Packet>(m_pktSize - header.GetSerializedSize());
    // Trace before adding header, for consistency with PacketSink
    m_txTraceWithSeqTsSize(packet, from, to, header);
    packet->AddHeader(header);
  } else {
    packet = Create<Packet>(m_pktSize);
  }

  int actual = m_socket->Send(packet);
  if ((unsigned)actual == m_pktSize) {
    m_txTrace(packet);
    m_totBytes += m_pktSize;
    m_unsentPacket = 0;
    Address localAddress;
    m_socket->GetSockName(localAddress);
    if (InetSocketAddress::IsMatchingType(m_peer)) {
      NS_LOG_DEBUG("node" << m_socket->GetNode()->GetId());
      NS_LOG_INFO("At time " << Simulator::Now().As(Time::S)
                             << " on-off application sent " << packet->GetSize()
                             << " bytes to "
                             << InetSocketAddress::ConvertFrom(m_peer).GetIpv4()
                             << " port "
                             << InetSocketAddress::ConvertFrom(m_peer).GetPort()
                             << " total Tx " << m_totBytes << " bytes");
      m_txTraceWithAddresses(packet, localAddress,
                             InetSocketAddress::ConvertFrom(m_peer));
    } else if (Inet6SocketAddress::IsMatchingType(m_peer)) {
      NS_LOG_INFO("At time "
                  << Simulator::Now().As(Time::S) << " on-off application sent "
                  << packet->GetSize() << " bytes to "
                  << Inet6SocketAddress::ConvertFrom(m_peer).GetIpv6()
                  << " port "
                  << Inet6SocketAddress::ConvertFrom(m_peer).GetPort()
                  << " total Tx " << m_totBytes << " bytes");
      m_txTraceWithAddresses(packet, localAddress,
                             Inet6SocketAddress::ConvertFrom(m_peer));
    }
  } else {
    NS_LOG_DEBUG("Unable to send packet; actual "
                 << actual << " size " << m_pktSize
                 << "; caching for later attempt");
    m_unsentPacket = packet;
  }
  m_residualBits = 0;
  m_lastStartTime = Simulator::Now();
  ScheduleNextTx();
}

void RandomOnOffApplication::ConnectionSucceeded(Ptr<Socket> socket) {
  NS_LOG_FUNCTION(this << socket);
  m_connected = true;
}

void RandomOnOffApplication::ConnectionFailed(Ptr<Socket> socket) {
  NS_LOG_FUNCTION(this << socket);
  NS_FATAL_ERROR("Can't connect");
}

}  // Namespace ns3
