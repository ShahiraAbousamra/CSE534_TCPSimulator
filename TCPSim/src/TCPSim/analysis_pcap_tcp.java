package TCPSim;

import java.nio.ByteBuffer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.Date;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.IOException;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

public class analysis_pcap_tcp {

	public enum TCP_PHASE {
	    Handshake,
	    InitialWindow,
	    SlowStart, 
	    CongAvoidance,
	    Loss
	}
	
	public String packetFilename = "";
	public String flowFilename = "";
	public String transactionFilename = "";
	public String retransmissonsFilename = "";
	public FileWriter packetFileWriter;
	public FileWriter flowFileWriter;
	public FileWriter transactionFileWriter;
	public FileWriter retransmissonsFileWriter;
	public PrintWriter packetPrintWriter ;
	public PrintWriter flowPrintWriter;
	public PrintWriter transactionPrintWriter;
	public PrintWriter retransmissonsPrintWriter;

	public ArrayList<MyTCPPacket> packets; 
	public ArrayList<MyTCPFlow> flows ; 

	public static void writeToFile(PrintWriter writer, String text){
		writer.write(text);
		writer.flush();
	}
	
	public static MyTCPPacket parsePacket(byte[] packetHeader, byte[] packetPayload, byte[] sourceIP, byte[] destinationIP, long totalPacketSize, long captureTS_ms){
		MyTCPPacket myPacket = new MyTCPPacket();
		
		// Get Source and Destination IP
		myPacket.srcIP = sourceIP;
		myPacket.destIP = destinationIP;
		for(int i=0; i<sourceIP.length; i++){
			myPacket.srcIP_str += (sourceIP[i] & 0xFF) + ".";
			myPacket.destIP_str += (destinationIP[i] & 0xFF) + ".";
		}
		myPacket.srcIP_str = myPacket.srcIP_str.substring(0, myPacket.srcIP_str.length()-1); 
		myPacket.destIP_str = myPacket.destIP_str.substring(0, myPacket.destIP_str.length()-1);
		myPacket.totalPacketSize = totalPacketSize;
		myPacket.captureTS_ms = captureTS_ms;
		
		// Get Segment length
		myPacket.headerLength = packetHeader.length;
		myPacket.payloadLength = packetPayload.length;


		// Parse the TCP header
		int currentByteNumber = 0;
		myPacket.srcPort = ((packetHeader[currentByteNumber] & 0xFF)<<8) + (packetHeader[currentByteNumber+1] & 0xFF);
		currentByteNumber += 2;
		myPacket.destPort = ((packetHeader[currentByteNumber] & 0xFF)<<8) + (packetHeader[currentByteNumber+1] & 0xFF);
		currentByteNumber += 2;
		myPacket.seqNum = ((long)(packetHeader[currentByteNumber] & 0xFF)<<24) + ((packetHeader[currentByteNumber+1] & 0xFF)<<16) + ((packetHeader[currentByteNumber+2] & 0xFF)<<8) + (packetHeader[currentByteNumber+3] & 0xFF);
		currentByteNumber += 4;
		myPacket.ackNum = ((long)(packetHeader[currentByteNumber] & 0xFF)<<24) + ((packetHeader[currentByteNumber+1] & 0xFF)<<16) + ((packetHeader[currentByteNumber+2] & 0xFF)<<8) + (packetHeader[currentByteNumber+3] & 0xFF);
		currentByteNumber += 4;
		myPacket.dataOffset = ((packetHeader[currentByteNumber] & 0xFF)>>4) ;
		myPacket.NS = ((packetHeader[currentByteNumber] & 0x01)) > 0? true: false ;
		currentByteNumber += 1;
		myPacket.CWR = ((packetHeader[currentByteNumber] & 0x80)) > 0? true: false ;
		myPacket.ECE = ((packetHeader[currentByteNumber] & 0x40)) > 0? true: false ;
		myPacket.URG = ((packetHeader[currentByteNumber] & 0x20)) > 0? true: false ;
		myPacket.ACK = ((packetHeader[currentByteNumber] & 0x10)) > 0? true: false ;
		myPacket.PSH = ((packetHeader[currentByteNumber] & 0x08)) > 0? true: false ;
		myPacket.RST = ((packetHeader[currentByteNumber] & 0x04)) > 0? true: false ;
		myPacket.SYN = ((packetHeader[currentByteNumber] & 0x02)) > 0? true: false ;
		myPacket.FIN = ((packetHeader[currentByteNumber] & 0x01)) > 0? true: false ;
		currentByteNumber += 1;
		myPacket.windowSize = ((packetHeader[currentByteNumber] & 0xFF)<<8) + (packetHeader[currentByteNumber+1] & 0xFF);
		myPacket.scaledWindowSize = myPacket.windowSize;
		
		currentByteNumber = 20;
		while(currentByteNumber < myPacket.dataOffset * 4){
			int value = (packetHeader[currentByteNumber] & 0xFF);
			if(value == 0) // 0 (8 bits): End of options list
				break;
			if(value == 1){ // 1 (8 bits): No operation (NOP, Padding)
				currentByteNumber++;
				continue;
			}
			if(value == 2 && myPacket.SYN){ // 2,4,SS (32 bits): Maximum segment size
				value = (packetHeader[currentByteNumber+1] & 0xFF);
				if(value != 4){
					currentByteNumber += 2;
					continue;
				}
				myPacket.MSS = ((packetHeader[currentByteNumber+2] & 0xFF)<<8) + (packetHeader[currentByteNumber+3] & 0xFF);
				currentByteNumber += 4;
				continue;
			}
			if(value == 3 && myPacket.SYN){ // 3,3,S (24 bits): Window Scale
				/*
				 * An option used to increase the maximum window size from 65,535 bytes to 1 gigabyte.
				 * The window scale option is used only during the TCP 3-way handshake. 
				 * The window scale value represents the number of bits to left-shift the 16-bit window size field. 
				 * The window scale value can be set from 0 (no shift) to 14 for each direction independently. 
				 * Both sides must send the option in their SYN segments to enable window scaling in either direction.
				 * */
				value = (packetHeader[currentByteNumber+1] & 0xFF);
				if(value != 3){
					currentByteNumber += 2;
					continue;
				}
				myPacket.windowScale = (packetHeader[currentByteNumber+2] & 0xFF);
				if(myPacket.windowScale > 0)
					myPacket.scaledWindowSize =myPacket.windowSize <<myPacket.windowScale ; 
				currentByteNumber += 3;
				continue;
			}
			if(value == 4 && myPacket.SYN){ // 4,2 (16 bits): Selective Acknowledgement permitted
				value = (packetHeader[currentByteNumber+1] & 0xFF);
				if(value == 2)
					myPacket.selectiveAck = true;
				currentByteNumber += 2;
				continue;
			}
			if(value == 5 ){ // 5,N,BBBB,EEEE,...: Selective ACKnowledgement (SACK) Blocks - BBBB: 4 bytes Begin, EEEE:4 bytes End
				/*
				 * (variable bits, N is either 10, 18, 26, or 34)- Selective ACKnowledgement (SACK)
					These first two bytes are followed by a list of 1–4 blocks being selectively acknowledged, 
					specified as 32-bit begin/end pointers
				 * */
				int N = (packetHeader[currentByteNumber+1] & 0xFF);
				N = N - 2; // 2 exclude the first 2 bytes for option type and number of SACKs
				myPacket.selectiveAckFrom = new long[N];
				myPacket.selectiveAckTo = new long[N];
				currentByteNumber += 2;
				for(int i=0; i<N; i++){
					myPacket.selectiveAckFrom[i] =((packetHeader[currentByteNumber] & 0xFF)<<8) + (packetHeader[currentByteNumber+1] & 0xFF);
					currentByteNumber += 4;
					myPacket.selectiveAckTo[i] =((packetHeader[currentByteNumber] & 0xFF)<<8) + (packetHeader[currentByteNumber+1] & 0xFF); 
					currentByteNumber += 4;
				}
				continue;
			}
			if(value == 8 ){ // 8,10,TTTT,EEEE (80 bits)- Timestamp and echo of previous timestamp
				value = (packetHeader[currentByteNumber+1] & 0xFF);
				if(value != 10){
					currentByteNumber += 2;
					continue;
				}
				currentByteNumber += 2;
				myPacket.senderTS = ((long)(packetHeader[currentByteNumber] & 0xFF)<<24) + ((packetHeader[currentByteNumber+1] & 0xFF)<<16) + ((packetHeader[currentByteNumber+2] & 0xFF)<<8) + (packetHeader[currentByteNumber+3] & 0xFF);;
				currentByteNumber += 4;
				myPacket.echoReceivedTS = ((long)(packetHeader[currentByteNumber] & 0xFF)<<24) + ((packetHeader[currentByteNumber+1] & 0xFF)<<16) + ((packetHeader[currentByteNumber+2] & 0xFF)<<8) + (packetHeader[currentByteNumber+3] & 0xFF);;
				currentByteNumber += 4;
				continue;
			}
		}
		return myPacket;
	}
	
	public static boolean updateFlows(MyTCPPacket myPacket, ArrayList<MyTCPFlow> myFlows){
		MyTCPFlow flow = null;


		if(myPacket.SYN && !myPacket.ACK){ 		// A new connection establishment 
			flow = new MyTCPFlow();
		
			flow.srcIP = myPacket.srcIP;
			flow.srcIP_str = myPacket.srcIP_str;
			flow.srcPort = myPacket.srcPort;

			flow.destIP = myPacket.destIP;
			flow.destIP_str = myPacket.destIP_str;
			flow.destPort = myPacket.destPort;
			
			flow.packetCountFromSrc++;
			flow.packetsSent.add(myPacket);
			flow.packets.add(myPacket);
			//flow.totalDataBytes_srcToDest += myPacket.headerLength + myPacket.payloadLength;
			flow.totalDataBytes_srcToDest += myPacket.totalPacketSize;
			flow.startTS_srcToDest = myPacket.headerLength + myPacket.payloadLength;
			flow.windowScaleSrc = myPacket.windowScale;
			flow.MSS = myPacket.MSS;
			myPacket.packetNumber = flow.packetCount;
			flow.packetCount++;
			myFlows.add(flow);
		}
		else{	// A flow should already exist
			// find if a flow already exists by comparing src (ip, port) and dest (ip, port) in both directions?? 
			for(int i=myFlows.size()-1; i>=0; i--){
				MyTCPFlow currentFlow = myFlows.get(i);
	//			if(currentFlow.Fin)
	//				continue;
				if(currentFlow.srcIP_str.equals(myPacket.srcIP_str) 
						&& currentFlow.srcPort == myPacket.srcPort
						&& currentFlow.destIP_str.equals(myPacket.destIP_str)
						&& currentFlow.destPort == myPacket.destPort){
					flow = currentFlow;
					flow.packetCountFromSrc++;
					flow.packetsSent.add(myPacket);
					flow.packets.add(myPacket);
					flow.totalDataBytes_srcToDest += myPacket.totalPacketSize;
					if(myPacket.SYN){
						flow.windowScaleSrc = myPacket.windowScale;
						flow.MSS = myPacket.MSS;
					}
					flow.packetCount++;
					myPacket.packetNumber = flow.packetCount;
					break;
				}				
				if(currentFlow.srcIP_str.equals(myPacket.destIP_str) 
						&& currentFlow.srcPort == myPacket.destPort
						&& currentFlow.destIP_str.equals(myPacket.srcIP_str)
						&& currentFlow.destPort == myPacket.srcPort){
					flow = currentFlow;
					flow.packetCountFromDest++;
					flow.packetsReceived.add(myPacket);
					flow.packets.add(myPacket);
					flow.totalDataBytes_destToSrc += myPacket.totalPacketSize;
					myPacket.fromClient = false;
					if(myPacket.SYN)
						flow.windowScaleDest = myPacket.windowScale;
					flow.packetCount++;
					myPacket.packetNumber = flow.packetCount;

					break;
				}				
			}
			if(flow == null){
				flow = new MyTCPFlow();
			
				flow.srcIP = myPacket.srcIP;
				flow.srcIP_str = myPacket.srcIP_str;
				flow.srcPort = myPacket.srcPort;
	
				flow.destIP = myPacket.destIP;
				flow.destIP_str = myPacket.destIP_str;
				flow.destPort = myPacket.destPort;
				
				flow.packetCountFromSrc++;
				flow.packetsSent.add(myPacket);
				flow.packets.add(myPacket);
				flow.totalDataBytes_srcToDest += myPacket.totalPacketSize;
				if(myPacket.SYN){
					flow.windowScaleSrc = myPacket.windowScale;
					flow.MSS = myPacket.MSS;
				}
				myFlows.add(flow);
				flow.packetCount++;
				myPacket.packetNumber = flow.packetCount;
			}
		}
		myPacket.flowID = flow.flowNum;
		if(myPacket.FIN)
			flow.Fin = true;
		return true;
	}

	public static boolean getTransaction(ArrayList<MyTCPPacket> myPackets, ArrayList<MyTCPFlow> myFlows, int flowNumber, int transactionNumber, PrintWriter file){
		MyTCPFlow flow = null;		
		for(int i=0 ; i<myFlows.size(); i++){
			if(myFlows.get(i).flowNum == flowNumber){
				flow = myFlows.get(i);
				break;
			}
		}
		if(flow == null)
			return false;
		MyTCPPacket packet1 = null, packet2 = null;
		long expectedAckNum = 0;
		int counter = 0;
		for(int i=0; i<myPackets.size(); i++){
			if(packet1 == null)
			{
				if(!myPackets.get(i).SYN && myPackets.get(i).fromClient && myPackets.get(i).flowID == flowNumber && myPackets.get(i).payloadLength > 0)
					counter++;
				if(counter == transactionNumber){
					packet1 = myPackets.get(i);
					expectedAckNum = packet1.seqNum + packet1.payloadLength;
				}
			}
			else{
				if(!myPackets.get(i).SYN && myPackets.get(i).ACK && !myPackets.get(i).fromClient && myPackets.get(i).flowID == flowNumber &&  myPackets.get(i).ackNum == expectedAckNum){
					packet2 = myPackets.get(i);
					break;
				}
			}			
		}
		
		writeToFile(file, "Flow Number = " + flowNumber + "\n");
		writeToFile(file, "Transaction Number = " + transactionNumber + "\n");
//		writeToFile(file, "From Client to Server:" + "\n");
//		if(packet1 != null){
//			writeToFile(file, "Sequence = " + packet1.seqNum 
//					+ "\t Ack = " + packet1.seqNum 
//					+ "\t Window Size = " + packet1.windowSize
//					+ "\t Window Scale = " + flow.windowScaleSrc
//					+ "\t Receive Window Size After Scaling = " + (packet1.windowSize << flow.windowScaleSrc)
//					+ "\n");
//		}
//		writeToFile(file, "From Server to Client:" + "\n");
//		if(packet2 != null){
//			writeToFile(file, "Sequence = " + packet2.seqNum 
//					+ "\t Ack = " + packet2.seqNum 
//					+ "\t Window Size = " + packet2.windowSize
//					+ "\t Window Scale = " + flow.windowScaleDest
//					+ "\t Receive Window Size After Scaling = " + (packet2.windowSize << flow.windowScaleSrc)
//					+ "\n\n");
//		}		
		if(packet1 != null && packet2!= null){
			writeToFile(file, "Sequence = " + packet1.seqNum 
					+ "\t Ack = " + packet2.ackNum 
					+ "\t Window Size = " + packet2.windowSize
					+ "\t Window Scale = " + flow.windowScaleDest
					+ "\t Receive Window Size After Scaling = " + (packet2.windowSize << flow.windowScaleDest)
					+ "\n\n");
		}
		return true;
	}
	
	public static long getThroughput(ArrayList<MyTCPPacket> myPackets, ArrayList<MyTCPFlow> myFlows, int flowNumber, PrintWriter file){
		MyTCPFlow flow = null;		
		long maxSequenceNumber = 0;
		long retransmissionCount = 0;
		String packetNums = "", packetIndxs = "";
		long startTime = 0, endTime = 0;
		long startTimeTCP = 0, endTimeTCP = 0;
		long retransmissionPacketLengths = 0;

		// Get the flow object
		for(int i=0 ; i<myFlows.size(); i++){
			if(myFlows.get(i).flowNum == flowNumber){
				flow = myFlows.get(i);
				break;
			}
		}
		if(flow == null)
			return 0;
		
		// Get the re-transmitted packets
		for(int i=0; i<myPackets.size(); i++){
			MyTCPPacket packet = myPackets.get(i);
			if(packet.flowID != flowNumber)
				continue;
			if(packet.fromClient)
			{
				//intermediatePacketsCount
				if(maxSequenceNumber == 0){
					maxSequenceNumber = packet.seqNum;
					startTimeTCP = packet.senderTS;
					endTimeTCP = packet.senderTS;
					startTime = packet.captureTS_ms;
					endTime = packet.captureTS_ms;
				}
				else if(packet.seqNum < maxSequenceNumber){
					retransmissionCount++;
					retransmissionPacketLengths += packet.totalPacketSize;
					packetNums += ", " + packet.packetNumber ;
					packetIndxs += ", " + (i+1) ;
					endTimeTCP = packet.senderTS;
					endTime = packet.captureTS_ms;
										
				}
				else{
					maxSequenceNumber = packet.seqNum;
					endTimeTCP = packet.senderTS;
					endTime = packet.captureTS_ms;
				}
					
			}
				
		}
		
//		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
//		Date endDate = new Date(endTime);
//		Date startDate = new Date(startTime);
//		System.out.println("start = " + dateFormat.format(startDate));
//		System.out.println("end = " + dateFormat.format(endDate));
//		
//		long sec = Duration.between(Instant.ofEpochSecond(startTime), Instant.ofEpochSecond(endTime)).getSeconds();
//		//System.out.println(dateFormat.format(endTime)); //2016/11/16 12:08:43
		
		long timePeriod = endTime - startTime; 
		long timePeriodTCP = endTimeTCP - startTimeTCP; 
		System.out.println("start TS = " + startTime); 
		System.out.println("End TS = " + endTime); 
		System.out.println("start TCP TS = " + startTimeTCP); 
		System.out.println("End TCP TS = " + endTimeTCP); 
		System.out.println("time period (ms) = " + timePeriod); 
		System.out.println("time period (TCP TS) = " + timePeriodTCP); 
		if(packetNums.length() > 0)
			packetNums = packetNums.substring(2);
		if(packetIndxs.length() > 0)
			packetIndxs = packetIndxs.substring(2);
		double throughput = (double)(flow.totalDataBytes_srcToDest - retransmissionPacketLengths) / (double)timePeriod; 
		double lossRate = (double)retransmissionCount / (double)flow.packetCountFromSrc;
//		String lossRate_str = String.format("%.10f", lossRate);
		writeToFile(file, "\tRe-transmission Count = " + retransmissionCount
				+ "\t packets Index In Flow = " + packetNums
				+ "\t packets Index In File= " + packetIndxs
				+ "\n\tTotal Re-transmitted Packet Lengths (bytes) = " + retransmissionPacketLengths 
				+ "\n\tTotal Transmitted Packet Lengths (bytes) = " + flow.totalDataBytes_srcToDest
				+ "\n\tTime Elapsed between first and last transmission in the flow (ms) = " + timePeriod				
				+ "\n\tTCP Clock time Elapsed between first and last transmission in the flow = " + timePeriodTCP				
				+ "\n\n\tThroughput (bytes/sec) = " + throughput * 1000
				+ "\n\tThroughput (Kbps) = " + throughput * 8
				+ "\n\tThroughput (Mbps) = " + throughput * 8 / 1000	
				+ "\n\n\tTotal Number of Packets Sent = " + flow.packetCountFromSrc
				+ "\n\tTotal Number of Packets Lost (Re-transmitted)= " + retransmissionCount
//				+ "\n\tLossRate str = " + lossRate_str
				+ "\n\tLossRate = " + lossRate
				+ "\n");
		
		flow.packetCountFromSrc_Retransmitted =retransmissionCount; 
		flow.lossRate =lossRate;
		
		return retransmissionCount ;
	}

	public static long getRetransmissionReason(ArrayList<MyTCPPacket> myPackets, MyTCPFlow flow, PrintWriter flowFile, PrintWriter retransmissionsFile){
		long maxSequenceNumber = 0;
		long retransmissionCount = 0;

		long lastAckNum = 0;
		int duplicateAckCount = 0;
		long retransmissionCount_timeout = 0, retransmissionCount_duplicateAck = 0;  
		
		writeToFile(retransmissionsFile, "\nFlowNumber = " + flow.flowNum
				+ "\n");

		// Get the re-transmitted packets
		for(int i=0; i<myPackets.size(); i++){
			MyTCPPacket packet = myPackets.get(i);
			if(packet.flowID != flow.flowNum )
				continue;
			if(packet.fromClient && packet.payloadLength > 0)
			{
				if(maxSequenceNumber == 0){
					maxSequenceNumber = packet.seqNum;
				}
				else if(packet.seqNum < maxSequenceNumber){
					retransmissionCount++;
					if(duplicateAckCount > 2 && packet.seqNum == lastAckNum){
						retransmissionCount_duplicateAck++;
						writeToFile(retransmissionsFile, "\tPacket Index in File = " + (i+1)
								+ "\t Sequence Num= " + packet.seqNum 
								+ "\t Cause = Duplicate Ack" 
								+ "\t Duplicate Ack Count = " + duplicateAckCount
								+ "\n");
					}
					else{
						int x;
						retransmissionCount_timeout++;
						if(duplicateAckCount > 2 )
							x = 0;
						if(packet.seqNum != lastAckNum)
							x = 0;
						writeToFile(retransmissionsFile, "\tPacket Index in File = " + (i+1)
								+ "\t Sequence Num= " + packet.seqNum 
								+ "\t Cause = Timeout" 
								+ "\t Duplicate Ack Count = " + duplicateAckCount
								+ "\n");
						duplicateAckCount = 0;
					}
					
										
				}
				else{
					maxSequenceNumber = packet.seqNum;
				}
					
			}
			else if(!packet.fromClient && packet.payloadLength == 0 && packet.ACK){
				if(packet.ackNum != lastAckNum){
					lastAckNum = packet.ackNum ;
					duplicateAckCount = 0;
				}
				else{
					duplicateAckCount++;
				}
					
			}
				
		}
		
		writeToFile(flowFile, "\n\tRe-transmission Count = " + retransmissionCount
				+ "\n\t Number of Re-transmission due to duplicate Ack = " + retransmissionCount_duplicateAck
				+ "\n\t Number of Re-transmission due to timeout = " + retransmissionCount_timeout
				+ "\n");
		
		
		return retransmissionCount ;
	}

	public static double getRTT(MyTCPFlow flow, PrintWriter file){
		
		// Estimate RTT using only packets sent in order (i.e. not re-transmitted)
		long maxSequenceNumber = 0;
		long maxAckNumber = 0;
		// for each Ack (if not a duplicate Ack) look for the corresponding sent packet
		// An ack = sequence + payload length
		
		int currentReceiveIndx = 0;
		long totalRTT_ms = 0;
		long totalRTT_packetCount = 0;
		double avgRTT = 0;
		for(int i=0; i<flow.packetsSent.size(); i++){
			MyTCPPacket packetSent = flow.packetsSent.get(i);
			if(maxSequenceNumber == 0 || (maxSequenceNumber < packetSent.seqNum && packetSent.payloadLength > 0)){
				maxSequenceNumber = packetSent.seqNum;
				long ackNum = packetSent.seqNum + packetSent.payloadLength;
				// look for corresponding ack
				for(int j=currentReceiveIndx; j<flow.packetsReceived.size(); j++){
					MyTCPPacket packetReceived = flow.packetsReceived.get(j);
					if(packetReceived.ACK && packetReceived.payloadLength == 0){ // Check that this is an ack
						if(packetReceived.ackNum == ackNum){ // This is my Ack (first ack received with the corresponding ack number)
							// Update totalRTT_ms and totalRTT_packetCount
							long RTTVal = packetReceived.captureTS_ms - packetSent.captureTS_ms;
							totalRTT_ms += packetReceived.captureTS_ms - packetSent.captureTS_ms;
							totalRTT_packetCount++;
							currentReceiveIndx = j + 1;
							break;
						}
						else if(packetReceived.ackNum > ackNum){ // This is a cumulative ack including this packets and some packets sent after - do not use it to estimate RTT
							currentReceiveIndx = j;
							break;
						}
						// otherwise packetReceived.ackNum < ackNum so continue looking for my Ack
					}
				}
			}
			else 
				continue;
		}
		
		avgRTT = (double)totalRTT_ms/(double)totalRTT_packetCount;
		flow.avgRTT = avgRTT;
		double throughput_theortical = (double)Math.sqrt(1.5/flow.lossRate) * (double)flow.MSS / flow.avgRTT * 8;
		
		writeToFile(file, "\n\tAverage RTT (ms) = " + avgRTT
				+ "\n");
		writeToFile(file, "\n\tTheoretical Troughput (kbps) = " + throughput_theortical
				+ "\n");
		
		
		return avgRTT;
	}

	public static long getCWnd(ArrayList<MyTCPPacket> myPackets, MyTCPFlow flow, PrintWriter file){
		long maxSequenceNumber = 0;
		long retransmissionCount = 0;
		String packetNums = "", packetIndxs = "";
		long startTime = 0, endTime = 0;
		long startTimeTCP = 0, endTimeTCP = 0;
		long retransmissionPacketLengths = 0;

		int icwnd = 0;
		long maxTimeBetweenConseqTrans = 0;
		long nextIndx = 0;
		TCP_PHASE phase = TCP_PHASE.Handshake;
		ArrayList<MyCWindow> cwnd_list = new ArrayList<MyCWindow>();

		
		MyCWindow currentCWnd = new MyCWindow();
		MyCWindow prevCWnd = null;
		int remainingInCWnd = 0;
		MyTCPPacket lastAckPacket = null;
		
		// Get Initial CWnd
		for(int i=0; i<myPackets.size(); i++){
			MyTCPPacket packet = myPackets.get(i);
			if(packet.flowID != flow.flowNum)
				continue;
			if(phase == TCP_PHASE.Handshake){
				if(maxSequenceNumber == 0){
					maxSequenceNumber = packet.seqNum;
				}
				else if(!packet.SYN){ // then this is the last ack of handshake
					phase = TCP_PHASE.InitialWindow;
					continue;
				}				
			}
			else if(phase == TCP_PHASE.InitialWindow){
				if(packet.fromClient && packet.payloadLength > 0){					
					if(packet.seqNum < maxSequenceNumber){
						phase = TCP_PHASE.Loss;
						// Close the prev window
						currentCWnd.endPacketNum_global = i;
						currentCWnd.endPacketNum_inFlow = myPackets.get(i).packetNumber;
						currentCWnd.endTime = myPackets.get(i).captureTS_ms;
						prevCWnd = currentCWnd;
						// Start a new window
						currentCWnd = new MyCWindow();
						currentCWnd.size = prevCWnd.size;
						currentCWnd.startPacketNum_global = i+1;
						currentCWnd.startPacketNum_inFlow = packet.packetNumber;
						currentCWnd.startTime = packet.captureTS_ms;
						cwnd_list.add(currentCWnd);
					}
					else
					{
						maxSequenceNumber = packet.seqNum; 
						icwnd++;
	//					cwnd++;
						if(currentCWnd.startPacketNum_global == 0){
							currentCWnd = new MyCWindow();
							currentCWnd.startPacketNum_global = i+1;
							currentCWnd.startPacketNum_inFlow = packet.packetNumber;
							currentCWnd.startTime = packet.captureTS_ms;
							cwnd_list.add(currentCWnd);
						}
						currentCWnd.size++;
					}
				}
				else if(!packet.fromClient && packet.payloadLength == 0 && packet.ACK){// start slow start when receive an ack (the initial window size has been sent)
//					currentCWnd.endPacketNum_global = i;
//					currentCWnd.endPacketNum_inFlow = packet.packetNumber;
//					currentCWnd.endTime = packet.captureTS_ms;
//					cwnd_list.add(currentCWnd);
//					prevCWnd = currentCWnd;
//					currentCWnd = new MyCWindow();
//					currentCWnd.size = prevCWnd.size;
					phase = TCP_PHASE.SlowStart;
					remainingInCWnd++;
				}
			}
			else if(phase == TCP_PHASE.SlowStart){
				if(packet.fromClient && packet.payloadLength > 0){
					if(packet.seqNum < maxSequenceNumber){
						phase = TCP_PHASE.Loss;
						// Close the prev window
						currentCWnd.endPacketNum_global = i;
						currentCWnd.endPacketNum_inFlow = myPackets.get(i-1).packetNumber;
						currentCWnd.endTime = myPackets.get(i-1).captureTS_ms;
						prevCWnd = currentCWnd;
						// Start a new window
						currentCWnd = new MyCWindow();
						currentCWnd.size = prevCWnd.size;
						currentCWnd.startPacketNum_global = i+1;
						currentCWnd.startPacketNum_inFlow = packet.packetNumber;
						currentCWnd.startTime = packet.captureTS_ms;
						cwnd_list.add(currentCWnd);
					}
					else{
						maxSequenceNumber = packet.seqNum;
						if(remainingInCWnd == 0){
							remainingInCWnd--;
							// Close the prev window
							currentCWnd.endPacketNum_global = i;
							currentCWnd.endPacketNum_inFlow = myPackets.get(i-1).packetNumber;
							currentCWnd.endTime = myPackets.get(i-1).captureTS_ms;
							prevCWnd = currentCWnd;
							// Start a new window
							currentCWnd = new MyCWindow();
							currentCWnd.size = prevCWnd.size;
							currentCWnd.size++;
							currentCWnd.startPacketNum_global = i+1;
							currentCWnd.startPacketNum_inFlow = packet.packetNumber;
							currentCWnd.startTime = packet.captureTS_ms;
							cwnd_list.add(currentCWnd);
						}
						else{
							if(remainingInCWnd < 0)
								currentCWnd.size++;
							remainingInCWnd--;
						}
					}
				}
				else if(!packet.fromClient && packet.payloadLength == 0 && packet.ACK){// Got an ack so update the remaining space in the sliding window
					if(remainingInCWnd < 0)
						remainingInCWnd = 1;
					else
						remainingInCWnd++;
					//lastAckPacket = packet;
				}
			}
			else if(phase == TCP_PHASE.Loss){
				if(packet.fromClient && packet.payloadLength > 0){
					if(packet.seqNum < maxSequenceNumber){
						phase = TCP_PHASE.Loss;
						// Close the prev window
						currentCWnd.endPacketNum_global = i;
						currentCWnd.endPacketNum_inFlow = myPackets.get(i-1).packetNumber;
						currentCWnd.endTime = myPackets.get(i-1).captureTS_ms;
						prevCWnd = currentCWnd;
						// Start a new window
						currentCWnd = new MyCWindow();
						currentCWnd.size = prevCWnd.size;
						currentCWnd.startPacketNum_global = i+1;
						currentCWnd.startPacketNum_inFlow = packet.packetNumber;
						currentCWnd.startTime = packet.captureTS_ms;
						cwnd_list.add(currentCWnd);
					}
					else{
						maxSequenceNumber = packet.seqNum; 
						if(remainingInCWnd > 0){
							remainingInCWnd--;
						}
						else{
							currentCWnd.size++;
							phase = TCP_PHASE.CongAvoidance;
						}
					}
										
				}
				else if(!packet.fromClient && packet.payloadLength == 0 && packet.ACK){// whenever receive an ack, reduce the window size by 1 until a packet is sent again
					currentCWnd.size--;
				}
				
			}
			else if(phase == TCP_PHASE.CongAvoidance){
				if(packet.fromClient && packet.payloadLength > 0){
					if(packet.seqNum < maxSequenceNumber){
						phase = TCP_PHASE.Loss;
						// Close the prev window
						currentCWnd.endPacketNum_global = i;
						currentCWnd.endPacketNum_inFlow = myPackets.get(i-1).packetNumber;
						currentCWnd.endTime = myPackets.get(i-1).captureTS_ms;
						prevCWnd = currentCWnd;
						// Start a new window
						currentCWnd = new MyCWindow();
						currentCWnd.size = prevCWnd.size;
						currentCWnd.startPacketNum_global = i+1;
						currentCWnd.startPacketNum_inFlow = packet.packetNumber;
						currentCWnd.startTime = packet.captureTS_ms;
						cwnd_list.add(currentCWnd);
					}
					else{
						maxSequenceNumber = packet.seqNum; 
						if(remainingInCWnd == 0){
							// Close the prev window
							currentCWnd.endPacketNum_global = i;
							currentCWnd.endPacketNum_inFlow = myPackets.get(i-1).packetNumber;
							currentCWnd.endTime = myPackets.get(i-1).captureTS_ms;
							prevCWnd = currentCWnd;
							// Start a new window
							currentCWnd = new MyCWindow();
							currentCWnd.size = prevCWnd.size;
							currentCWnd.size++;
							currentCWnd.startPacketNum_global = i+1;
							currentCWnd.startPacketNum_inFlow = packet.packetNumber;
							currentCWnd.startTime = packet.captureTS_ms;
							cwnd_list.add(currentCWnd);
						}
						else
							remainingInCWnd--;
					}
				}
			}
		}
		
		int printNum = Math.min(5,  cwnd_list.size());
		for(int i=0; i<printNum ; i++){
			MyCWindow cwnd = cwnd_list.get(i);
			writeToFile(file, "\tCongestion Window Number = " + (i+1)
					+ "\n\t\tSize = " + cwnd.size
					+ "\n\t\tstartPacketNum_inFlow = " + cwnd.startPacketNum_inFlow
					+ "\n\t\tendPacketNum_inFlow = " + cwnd.endPacketNum_inFlow
					+ "\n\t\tstartPacketNum_global= " + cwnd.startPacketNum_global
					+ "\n\t\tendPacketNum_global= " + cwnd.endPacketNum_global
					+ "\n"
					);
					
			
		}
		
		
		return cwnd_list.size();
	}

	public void AnalyzeFile(String filepath)  throws IOException {
		DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
		Date date = new Date();
		System.out.println(dateFormat.format(date)); //2016/11/16 12:08:43
		packetFilename = filepath.substring(0, filepath.length()-5) + "_packets_" + dateFormat.format(date) + ".txt";
		flowFilename = filepath.substring(0, filepath.length()-5) + "_flows_" + dateFormat.format(date) + ".txt";
		transactionFilename = filepath.substring(0, filepath.length()-5) + "_transactions_" + dateFormat.format(date) + ".txt";
		retransmissonsFilename = filepath.substring(0, filepath.length()-5) + "_retransmissons_" + dateFormat.format(date) + ".txt";
		MyTCPFlow.maxFlowNum = 0;
		
		try {
			packetFileWriter = new FileWriter(packetFilename, true);
			flowFileWriter = new FileWriter(flowFilename, true);
			transactionFileWriter = new FileWriter(transactionFilename, true);
			retransmissonsFileWriter = new FileWriter(retransmissonsFilename, true);
			packetPrintWriter = new PrintWriter(packetFileWriter);
			flowPrintWriter = new PrintWriter(flowFileWriter);
			transactionPrintWriter = new PrintWriter(transactionFileWriter);
			retransmissonsPrintWriter = new PrintWriter(retransmissonsFileWriter);
		} 
		catch (IOException e) {
			e.printStackTrace();
			throw e;
		}
		
		// Open the pcap file
		final StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(filepath, errbuf);
		if (pcap == null) {  
			System.err.println(errbuf); // Error is stored in errbuf if any  
	        return;  
		}

		packets = new ArrayList<MyTCPPacket>(); 
		flows = new ArrayList<MyTCPFlow>(); 

		int batchSize = 100;
		int count = 0;
		do{
			count = pcap.dispatch(batchSize, new JPacketHandler<StringBuilder>() {	
	            /** 
	             * We purposely define and allocate our working tcp header (accessor) 
	             * outside the dispatch function and thus the libpcap loop, as this type 
	             * of object is reusable and it would be a very big waist of time and 
	             * resources to allocate it per every dispatch of a packet. We mark it 
	             * final since we do not plan on allocating any other instances of Tcp. 
	             */  
	            final Tcp tcp = new Tcp();  
	  
	            /* 
	             * Same thing for our http header 
	             */  
	            final Http http = new Http();  
	            final Ip4 ip = new Ip4();
	  
	            /** 
	             * Our custom handler that will receive all the packets libpcap will 
	             * dispatch to us. This handler is inside a libpcap loop and will receive 
	             * exactly 10 packets as we specified on the Pcap.loop(10, ...) line 
	             * above. 
	             *  
	             * @param packet 
	             *          a packet from our capture file 
	             * @param errbuf 
	             *          our custom user parameter which we chose to be a StringBuilder 
	             *          object, but could have chosen anything else we wanted passed 
	             *          into our handler by libpcap 
	             */  
	            public void nextPacket(JPacket packet, StringBuilder errbuf) {  
	                /* 
	                 * Here we receive 1 packet at a time from the capture file. We are 
	                 * going to check if we have a tcp packet and do something with tcp 
	                 * header. We are actually going to do this twice to show 2 different 
	                 * ways how we can check if a particular header exists in the packet and 
	                 * then get that header (peer header definition instance with memory in 
	                 * the packet) in 2 separate steps. 
	                 */ 
	            	byte[] TCP_header, TCP_Payload;
	                if (packet.hasHeader(Tcp.ID)) {  
	                    packet.getHeader(tcp);
	                    int headerOffset = tcp.getHeaderOffset();
	                    int headerLength = tcp.getHeaderLength();
	                    int payloadOffset = tcp.getPayloadOffset();
	                    int payloadLength = tcp.getPayloadLength();
	                	TCP_header = packet.getByteArray(headerOffset, headerLength);
	                	TCP_Payload = packet.getByteArray(payloadOffset, payloadLength);
	                	
	                	long captureTS_ms = packet.getCaptureHeader().timestampInMillis();	                	
	                	packet.getHeader(ip);
	                	MyTCPPacket myPacket = parsePacket(TCP_header, TCP_Payload, ip.source(), ip.destination(), packet.getPacketWirelen(), captureTS_ms);
	                	packets.add(myPacket);
	                	updateFlows(myPacket, flows);
	            		writeToFile(packetPrintWriter, myPacket.toString());
	                }  
	  
//	                /* 
//	                 * An easier way of checking if header exists and peering with memory 
//	                 * can be done using a conveniece method JPacket.hasHeader(? extends 
//	                 * JHeader). This method performs both operations at once returning a 
//	                 * boolean true or false. True means that header exists in the packet 
//	                 * and our tcp header difinition object is peered or false if the header 
//	                 * doesn't exist and no peering was performed. 
//	                 */  
//	                if (packet.hasHeader(tcp)) {  
//	                    System.out.printf("tcp header::%s%n", tcp.toString());  
//	                }  
	//  
//	                /* 
//	                 * A typical and common approach to getting headers from a packet is to 
//	                 * chain them as a condition for the if statement. If we need to work 
//	                 * with both tcp and http headers, for example, we place both of them on 
//	                 * the command line. 
//	                 */  
//	                if (packet.hasHeader(tcp) && packet.hasHeader(http)) {  
//	                    /* 
//	                     * Now we are guarranteed to have both tcp and http header peered. If 
//	                     * the packet only contained tcp segment even though tcp may have http 
//	                     * port number, it still won't show up here since headers appear right 
//	                     * at the beginning of http session. 
//	                     */  
	//  
//	                    System.out.printf("http header::%s%n", http);  
	//  
//	                    /* 
//	                     * jNetPcap keeps track of frame numbers for us. The number is simply 
//	                     * incremented with every packet scanned. 
//	                     */  
	//  
//	                }  
	//  
//	                System.out.printf("frame #%d%n", packet.getFrameNumber());  
	            }  
	  
	        }, errbuf);  
		} while (count >= batchSize);
		  

		System.out.println("Number of Flows = " + flows.size());
		
		for(int i=0; i<flows.size(); i++){
			MyTCPFlow flow = flows.get(i);
			writeToFile(flowPrintWriter, "Flow Number = " + flow.flowNum + "\n"); 
			writeToFile(flowPrintWriter, flow.toString());
			getTransaction(packets, flows, flow.flowNum, 1, transactionPrintWriter);
			getTransaction(packets, flows, flow.flowNum, 2, transactionPrintWriter);
			getThroughput(packets, flows, flow.flowNum, flowPrintWriter);
			getRTT(flow, flowPrintWriter);
			getCWnd(packets, flow, flowPrintWriter);
			getRetransmissionReason(packets, flow, flowPrintWriter, retransmissonsPrintWriter);
			writeToFile(flowPrintWriter, "\n"); 
		}
		
		

		flowPrintWriter.close();
		packetPrintWriter.close();
		transactionPrintWriter.close();
		retransmissonsPrintWriter.close();
		flowFileWriter.close();
		packetFileWriter.close();
		transactionFileWriter.close();
		retransmissonsFileWriter.close();
		
	}
	

}
