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

//
// This is an illustration of how one could use virtualization techniques to
// allow running applications on virtual machines talking over simulated
// networks.
//
// The actual steps required to configure the virtual machines can be rather
// involved, so we don't go into that here.  Please have a look at one of
// our HOWTOs on the nsnam wiki for more details about how to get the 
// system confgured.  For an example, have a look at "HOWTO Use Linux 
// Containers to set up virtual networks" which uses this code as an 
// example.
//
// The configuration you are after is explained in great detail in the 
// HOWTO, but looks like the following:
//
//  +----------+                           +----------+
//  | virtual  |                           | virtual  |
//  |  Linux   |                           |  Linux   |
//  |   Host   |                           |   Host   |
//  |          |                           |          |
//  |   eth0   |                           |   eth0   |
//  +----------+                           +----------+
//       |                                      |
//  +----------+                           +----------+
//  |  Linux   |                           |  Linux   |
//  |  Bridge  |                           |  Bridge  |
//  +----------+                           +----------+
//       |                                      |
//  +------------+                       +-------------+
//  | "tap-left" |                       | "tap-right" |
//  +------------+                       +-------------+
//       |           n0            n1           |
//       |       +--------+    +--------+       |
//       +-------|  tap   |    |  tap   |-------+
//               | bridge |    | bridge |
//               +--------+    +--------+
//               |  wifi  |    |  wifi  |
//               +--------+    +--------+
//                   |             |
//                 ((*))         ((*))
//
//                       Wifi LAN
//
//                        ((*))
//                          |
//                     +--------+
//                     |  wifi  |
//                     +--------+
//                     | access |
//                     |  point |
//                     +--------+
//
#include <iostream>
#include <fstream>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/tap-bridge-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TapWifiVirtualMachineExample");

int 
main (int argc, char *argv[])
{
  CommandLine cmd;
  cmd.Parse (argc, argv);

  //
  // We are interacting with the outside, real, world.  This means we have to 
  // interact in real-time and therefore means we have to use the real-time
  // simulator and take the time to calculate checksums.
  //
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  //
  // Create two ghost nodes.  The first will represent the virtual machine host
  // on the left side of the network; and the second will represent the VM on 
  // the right side.
  //
  NodeContainer nodes;
  nodes.Create(10);

  //
  // We're going to use 802.11 A so set up a wifi helper to reflect that.
  //
  WifiHelper wifi = WifiHelper::Default ();
  wifi.SetStandard (WIFI_PHY_STANDARD_80211a);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue ("OfdmRate54Mbps"));

  //
  // No reason for pesky access points, so we'll use an ad-hoc network.
  //
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifiMac.SetType ("ns3::AdhocWifiMac");

  //
  // Configure the physcial layer.
  //
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());

  //
  // Install the wireless devices onto our ghost nodes.
  //
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);

  //
  // We need location information since we are talking about wifi, so add a
  // constant position to the ghost nodes.
  //
 // MobilityHelper mobility;
 // Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
 // positionAlloc->Add (Vector (0.0, 0.0, 0.0));
 // positionAlloc->Add (Vector (5.0, 0.0, 0.0));
 // mobility.SetPositionAllocator (positionAlloc);
 // mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue (1.0),
                                 "MinY", DoubleValue (1.0),
                                 "DeltaX", DoubleValue (5.0),
                                 "DeltaY", DoubleValue (5.0),
                                 "GridWidth", UintegerValue (3),
                                 "LayoutType", StringValue ("RowFirst"));
                                 
  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel",
                             "Mode", StringValue ("Time"),
                             "Time", StringValue ("2s"),
                             "Speed", StringValue ("ns3::ConstantRandomVariable[Constant=3.0]"),
                             "Bounds", RectangleValue (Rectangle (0.0, 50.0, 0.0, 50.0)));



  mobility.Install (nodes);

  //
  // Use the TapBridgeHelper to connect to the pre-configured tap devices for 
  // the left side.  We go with "UseLocal" mode since the wifi devices do not
  // support promiscuous mode (because of their natures0.  This is a special
  // case mode that allows us to extend a linux bridge into ns-3 IFF we will
  // only see traffic from one other device on that bridge.  That is the case
  // for this configuration.
  //
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("UseLocal"));



  //running containers
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-9")); 
 tapBridge.Install (nodes.Get (9), devices.Get (9));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-8")); 
 tapBridge.Install (nodes.Get (8), devices.Get (8));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-7")); 
 tapBridge.Install (nodes.Get (7), devices.Get (7));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-6")); 
 tapBridge.Install (nodes.Get (6), devices.Get (6));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-5")); 
 tapBridge.Install (nodes.Get (5), devices.Get (5));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-4")); 
 tapBridge.Install (nodes.Get (4), devices.Get (4));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-3")); 
 tapBridge.Install (nodes.Get (3), devices.Get (3));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-2")); 
 tapBridge.Install (nodes.Get (2), devices.Get (2));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-1")); 
 tapBridge.Install (nodes.Get (1), devices.Get (1));
tapBridge.SetAttribute ("DeviceName", StringValue ("tap-olsrd-0")); 
 tapBridge.Install (nodes.Get (0), devices.Get (0));







  //
  // Run the simulation for ten minutes to give the user time to play around
  //
  Simulator::Stop (Seconds (300.));
  Simulator::Run ();
  Simulator::Destroy ();
}
