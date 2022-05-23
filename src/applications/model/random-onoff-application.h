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

#ifndef RANDOMONOFF_APPLICATION_H
#define RANDOMONOFF_APPLICATION_H

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/data-rate.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/seq-ts-size-header.h"
#include "ns3/traced-callback.h"

namespace ns3 {

class Address;
class RandomVariableStream;
class Socket;

class RandomOnOffApplication : public Application {
 public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId(void);

  RandomOnOffApplication();

  virtual ~RandomOnOffApplication();

  /**
   * \brief Set the total number of bytes to send.
   *
   * Once these bytes are sent, no packet is sent again, even in on state.
   * The value zero means that there is no limit.
   *
   * \param maxBytes the total number of bytes to send
   */
  void SetMaxBytes(uint64_t maxBytes);

  /**
   * \brief Return a pointer to associated socket.
   * \return pointer to associated socket
   */
  Ptr<Socket> GetSocket(void) const;

  /**
   * \brief Assign a fixed random variable stream number to the random variables
   * used by this model.
   *
   * \param stream first stream index to use
   * \return the number of stream indices assigned by this model
   */
  int64_t AssignStreams(int64_t stream);

 protected:
  virtual void DoDispose(void);

 private:
  // inherited from Application base class.
  virtual void StartApplication(void);  // Called at time specified by Start
  virtual void StopApplication(void);   // Called at time specified by Stop

  // helpers
  /**
   * \brief Cancel all pending events.
   */
  void CancelEvents();

  // Event handlers
  /**
   * \brief Start an On period
   */
  void StartSending();
  /**
   * \brief Start an Off period
   */
  void StopSending();
  /**
   * \brief Send a packet
   */
  void SendPacket();

  Ptr<Socket> m_socket;                    //!< Associated socket
  Address m_peer;                          //!< Peer address
  Address m_local;                         //!< Local address to bind to
  bool m_connected;                        //!< True if connected
  Ptr<RandomVariableStream> m_onTime;      //!< rng for On Time
  Ptr<RandomVariableStream> m_offTime;     //!< rng for Off Time
  Ptr<RandomVariableStream> m_intervalRng;    //!< rng for send interval
  Ptr<RandomVariableStream> m_pktSizeRng;  //!< rng for packet size
  DataRate m_cbrRate;                      //!< Rate that data is generated
  DataRate m_cbrRateFailSafe;  //!< Rate that data is generated (check copy)
  uint32_t m_pktSize;          //!< Size of packets
  uint32_t m_residualBits;     //!< Number of generated, but not sent, bits
  Time m_lastStartTime;        //!< Time last packet sent
  uint64_t m_maxBytes;         //!< Limit total number of bytes sent
  uint64_t m_totBytes;         //!< Total bytes sent so far
  EventId m_startStopEvent;    //!< Event id for next start or stop event
  EventId m_sendEvent;         //!< Event id of pending "send packet" event
  TypeId m_tid;                //!< Type of the socket used
  uint32_t m_seq{0};           //!< Sequence
  Ptr<Packet> m_unsentPacket;  //!< Unsent packet cached for future attempt
  bool m_enableSeqTsSizeHeader{
      false};  //!< Enable or disable the use of SeqTsSizeHeader

  /// Traced Callback: transmitted packets.
  TracedCallback<Ptr<const Packet>> m_txTrace;

  /// Callbacks for tracing the packet Tx events, includes source and
  /// destination addresses
  TracedCallback<Ptr<const Packet>, const Address &, const Address &>
      m_txTraceWithAddresses;

  /// Callback for tracing the packet Tx events, includes source, destination,
  /// the packet sent, and header
  TracedCallback<Ptr<const Packet>, const Address &, const Address &,
                 const SeqTsSizeHeader &>
      m_txTraceWithSeqTsSize;

 private:
  /**
   * \brief Schedule the next packet transmission
   */
  void ScheduleNextTx();
  /**
   * \brief Schedule the next On period start
   */
  void ScheduleStartEvent();
  /**
   * \brief Schedule the next Off period start
   */
  void ScheduleStopEvent();
  /**
   * \brief Handle a Connection Succeed event
   * \param socket the connected socket
   */
  void ConnectionSucceeded(Ptr<Socket> socket);
  /**
   * \brief Handle a Connection Failed event
   * \param socket the not connected socket
   */
  void ConnectionFailed(Ptr<Socket> socket);
};

}  // namespace ns3

#endif /* RANDOMONOFF_APPLICATION_H */
