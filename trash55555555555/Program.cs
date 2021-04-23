using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Packets.Http;
using System.IO;
namespace trash55555555555
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                #region Main Sniffer
                // Retrieve the device list from the local machine
                IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

                if (allDevices.Count == 0)
                {
                    Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                    return;
                }

                // Print the list
                for (int i = 0; i != allDevices.Count; ++i)
                {
                    LivePacketDevice device = allDevices[i];
                    Console.Write((i + 1) + ". " + device.Name);
                    if (device.Description != null)
                        Console.WriteLine(" (" + device.Description + ")");
                    else
                        Console.WriteLine(" (No description available)");
                }

                int deviceIndex = 0;
                do
                {
                    Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                    string deviceIndexString = Console.ReadLine();
                    if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                        deviceIndex < 1 || deviceIndex > allDevices.Count)
                    {
                        deviceIndex = 0;
                    }
                } while (deviceIndex == 0);

                // Take the selected adapter
                
                PacketDevice selectedDevice = allDevices[deviceIndex - 1];

                // Open the device
                using (PacketCommunicator communicator =
                    selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                                // 65536 guarantees that the whole packet will be captured on all the link layers
                                        PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                        25))                                  // read timeout
                {
                    Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                    // Retrieve the packets
                    Packet packet;
                    do
                    {
                        PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                        switch (result)
                        {
                            case PacketCommunicatorReceiveResult.Timeout:
                                // Timeout elapsed
                                continue;
                            case PacketCommunicatorReceiveResult.Ok:
                                
                                //Console.WriteLine(ip.IpV4.Source + "  " + icmp.MessageType + "  " + icmp.Length);

                                //Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" +
                                //                   packet.Length + packet.Ethernet.IpV4 + "  " + packet.IpV4.Tcp.Payload + "\\n");
                                
                                    

                                if (packet.Ethernet.IpV4.Source.ToString() == "192.168.10.9" && packet.Ethernet.IpV4.Icmp.IsValid)
                                {
                                    // Console.WriteLine("Source:  " + packet.Ethernet.IpV4.Source + "  " + packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"));
                                    // Console.WriteLine("Destination:  " + packet.Ethernet.IpV4.Destination + "  " + packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"));


                                    //Console.WriteLine("Destination:  " + packet.Ethernet.IpV4.Protocol);
                                    //Console.WriteLine("Tcp Valid :  " + packet.IpV4.Tcp.IsValid);
                                    //Console.WriteLine("Udp Valid :  " + packet.IpV4.Udp.IsValid);
                                    Console.WriteLine("Ethernet Payload :  " + packet.Ethernet.Payload);
                                    Console.WriteLine("Icmp.MessageType :  " + packet.Ethernet.IpV4.Icmp.MessageType + "  " + packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff"));

                                    if (packet.Ethernet.IpV4.Icmp.MessageType.ToString() != "Echo")
                                    {
                                        //Block in Firewall
                                    }






                                }



                                //#region Capture File
                                //using (PacketDumpFile dumpFile = communicator.OpenDump("cap.file"))
                                //{
                                //    Console.WriteLine("Listening on " + selectedDevice.Description + "... Press Ctrl+C to stop...");

                                //    // start the capture
                                //    communicator.ReceivePackets(0, dumpFile.Dump);
                                //}
                                //#endregion


                                //#region read File cap
                                //using (PacketDumpFile dumpFile = communicator.OpenDump("rrr"))
                                //{
                                //    communicator.ReceivePackets(0, DispatcherHandler);
                                //}
                                //#endregion



                                // print ip addresses and udp ports
                                // Console.WriteLine(ip.Source + ":" + udp.SourcePort + " -> " + ip.Destination + ":" + udp.DestinationPort);

                                break;
                            default:
                                throw new InvalidOperationException("The result " + result + " shoudl never be reached here");
                        }
                    } while (true);
                }

                #endregion


            }
            catch (Exception ex)
            {

                if (File.Exists(@"log.txt"))
                {
                    string file_name = @"log.txt";
                    string error_text = ex.Message;

                    File.WriteAllText(file_name,error_text);
                }
                else
                {
                    string file_name = @"log.txt";
                    string error_text = ex.Message;

                    File.WriteAllText(file_name, error_text);
                }
                 
            }



        }

        private static void DispatcherHandler(Packet packet)
        {
            // print packet timestamp and packet length
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);

            // Print the packet
            const int LineLength = 64;
            for (int i = 0; i != packet.Length; ++i)
            {
                Console.Write((packet[i]).ToString("X2"));
                if ((i + 1) % LineLength == 0)
                    Console.WriteLine();
            }

            Console.WriteLine();
            Console.WriteLine();
        }


    }
}
