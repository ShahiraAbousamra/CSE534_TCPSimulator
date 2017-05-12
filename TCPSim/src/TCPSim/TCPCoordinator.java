/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.PriorityQueue;
import java.util.Queue;
import java.util.concurrent.ExecutionException;

public class TCPCoordinator {

	public static String traceFilePath = ""; 
	// end points
	// config
	// events list(s) stack
	// get next event
	// each end point insert in its event list
	
	public static ArrayList<MyTCPPacket> packetsList; 
	public static ArrayList<MyTCPFlow> flowsList ;
	public static long currentTime = 0;
	public static double rtt = 0; // input
	public static double rtt_original = 0; // input
	public static double rttDiv2 = 0; // calc from input
	public static double rtt1 = 0; // input
	public static double rtt1Div2 = 0; // calc from input
	public static double rtt2 = 0; // input
	public static double rtt2Div2 = 0; // calc from input
	public static double switchingDelay = 0; // input
	public static int routerBufferSize = 0; // input
	public static double lossRate = 0; // input
	public static double bandwidth = 10; // input
	//public static long RTO = 0; // input // use rtt*2
	public static ArrayList<Integer> currFlowPacketList ;
	public static int currFlowIndx;
	public static int initialCongWindowSize = 0;	// input
	public static int slowStartThreshold = 0; 	// input
	public static int MSS = 0; 	// input
	public static int currentFlowLastSentPacketIndx = -1; 	// input
	public static PrintWriter eventLogWriter = null;
	public static String eventLogFilename = "";
	public static PrintWriter eventLogWriter_css = null;
	public static String eventLogFilename_css = "";
	public static PrintWriter cwndLogWriter_client = null;
	public static String cwndLogFilename_client = "";
	public static PrintWriter cwndLogWriter_server = null;
	public static String cwndLogFilename_server = "";
	public static TopologyConfig topologyConfig  = TopologyConfig.CLIENT_SERVER;
	public static TCPStatistics tcpStatistics = null;
	public static PrintWriter inflightLogWriter_client = null;
	public static String inflightLogFilename_client = "";
	public static PrintWriter inflightLogWriter_server = null;
	public static String inflightLogFilename_server = "";
	public static PrintWriter inflightTimeLogWriter_client = null;
	public static String inflightTimeLogFilename_client = "";
	public static PrintWriter inflightTimeLogWriter_server = null;
	public static String inflightTimeLogFilename_server = "";
		
//	public static Queue<LogEvent> loqQ = new LinkedList<LogEvent>();
//	public static int maxlogQSize = 500;

	public TCPCoordinator(){
		
	}
	
	public static void useFile(String traceFilePath) throws IOException{
		if(eventLogWriter != null){
			eventLogWriter.close();
			eventLogWriter = null;
		}
		if(eventLogWriter_css != null){
			eventLogWriter_css.close();
			eventLogWriter_css = null;
		}
		if(cwndLogWriter_client != null){
			cwndLogWriter_client.close();
			cwndLogWriter_client= null;
		}
		if(cwndLogWriter_server != null){
			cwndLogWriter_server.close();
			cwndLogWriter_server= null;
		}
		if(inflightLogWriter_client != null){
			inflightLogWriter_client.close();
			inflightLogWriter_client= null;
		}
		if(inflightLogWriter_server != null){
			inflightLogWriter_server.close();
			inflightLogWriter_server= null;
		}
		if(inflightTimeLogWriter_client != null){
			inflightTimeLogWriter_client.close();
			inflightTimeLogWriter_client= null;
		}
		if(inflightTimeLogWriter_server != null){
			inflightTimeLogWriter_server.close();
			inflightTimeLogWriter_server= null;
		}
		tcpStatistics = new TCPStatistics(); 
		TCPCoordinator.traceFilePath = traceFilePath;
    	analysis_pcap_tcp pcapAnalyzer = new analysis_pcap_tcp();
    	pcapAnalyzer.AnalyzeFile(traceFilePath);
    	packetsList = pcapAnalyzer.packets;
    	flowsList = pcapAnalyzer.flows;
    	currentFlowLastSentPacketIndx = -1;
    	currFlowPacketList = new ArrayList<Integer>(flowsList.size());
    	while(currFlowPacketList.size() < flowsList.size()) currFlowPacketList.add(0);
    	
    	simulateFlow(flowsList.get(0));
	}
	
	public static void setConfig(TopologyConfig topologyConfig, double rtt, double bandwidth, int mss, int initialCongWindowSize, int slowStartThresh, double lossRate){
		TCPCoordinator.rtt = rtt;
		TCPCoordinator.rtt_original = rtt;
		TCPCoordinator.rttDiv2 = rtt/2;
		TCPCoordinator.bandwidth = bandwidth/8; // Kbps convert to Bytes per ms
		TCPCoordinator.MSS = mss;
		TCPCoordinator.initialCongWindowSize = initialCongWindowSize; 
		TCPCoordinator.slowStartThreshold = slowStartThresh;
		TCPCoordinator.lossRate = lossRate/100;
		TCPCoordinator.topologyConfig = topologyConfig;
		if(TCPCoordinator.tcpStatistics == null)
			TCPCoordinator.tcpStatistics = new TCPStatistics();
		TCPCoordinator.tcpStatistics.totalSampleRTT += rtt;
		TCPCoordinator.tcpStatistics.SampleRTTCount ++;
				
	}
	
	public static void setConfig(TopologyConfig topologyConfig, double rtt1, double rtt2, double switchingDelay, double bandwidth, int mss, int initialCongWindowSize, int slowStartThresh, int bufferSize){
		TCPCoordinator.rtt1 = rtt1;
		TCPCoordinator.rtt1Div2 = rtt1/2;
		TCPCoordinator.rtt2 = rtt2;
		TCPCoordinator.rtt2Div2 = rtt2/2;
		TCPCoordinator.switchingDelay= 1/switchingDelay * 1000; // ms per packet
		TCPCoordinator.rtt = rtt1+TCPCoordinator.switchingDelay*2+rtt2;
		TCPCoordinator.rtt_original = rtt;
		TCPCoordinator.rttDiv2 = rtt/2;
		TCPCoordinator.bandwidth = bandwidth/8; // Kbps convert to Bytes per ms
		TCPCoordinator.MSS = mss;
		TCPCoordinator.initialCongWindowSize = initialCongWindowSize; 
		TCPCoordinator.slowStartThreshold = slowStartThresh;
		TCPCoordinator.lossRate = 0;
		TCPCoordinator.topologyConfig = topologyConfig;
		TCPCoordinator.routerBufferSize = bufferSize;
		if(TCPCoordinator.tcpStatistics == null)
			TCPCoordinator.tcpStatistics = new TCPStatistics();
		TCPCoordinator.tcpStatistics.totalSampleRTT += rtt;
		TCPCoordinator.tcpStatistics.SampleRTTCount ++;
	}

	public static void simulateFlow(MyTCPFlow flow){
		if(flow == null || flow.packets == null || flow.packets.size() <= 0)
			return;
		
		TCPEndPoint client = new TCPEndPoint(flow.srcIP_str, true, "client"); 
		TCPEndPoint server = new TCPEndPoint(flow.destIP_str, false, "server");
		TCPRouter router = null;
		if(topologyConfig == TopologyConfig.CLIENT_ROUTER_SERVER)
			router = new TCPRouter("", routerBufferSize, switchingDelay, "router"); 
		
		// setup the send and receive windows for client and server
		boolean synProcessed = false, synAckProcessed = false;
		int nextPacketIndx = 0; 
		for(int i=0; i<flow.packets.size(); i++){
			MyTCPPacket packet = flow.packets.get(i);
			if(packet.SYN && !packet.ACK){ // client sent a SYN to the server
				client.receiveCWnd.scale = packet.windowScale;
				int windowSize = (int)packet.scaledWindowSize;
//				int windowSize = (int)packet.windowSize;
				client.receiveCWnd.setMaxReceiveBufferSize((int)windowSize);
//				client.lastSeqNumSent = packet.seqNum;
//				client.sendCWnd.lastFrameSent = packet.seqNum + packet.headerLength + packet.payloadLength;
				client.sendCWnd.lastFrameSent = packet.seqNum + packet.payloadLength + 1;
//				client.sendCWnd.lastAckReceived= packet.seqNum + packet.headerLength + packet.payloadLength;
				client.sendCWnd.lastAckReceived= packet.seqNum + packet.payloadLength + 1;

				server.sendCWnd.scale = packet.windowScale;
				server.sendCWnd.setMaxWndSize(windowSize);
				server.sendCWnd.receiverCurrentWndSize = windowSize; 
//				server.sendCWnd.maxWndSize = windowSize;
				//server.sendCWnd.currentCWndSize = packet.windowSize;
//				server.lastAckNumSent = packet.seqNum + packet.headerLength + packet.payloadLength;
//				server.receiveCWnd.setMinAcceptablePacket((packet.seqNum + packet.headerLength + packet.payloadLength));
				server.receiveCWnd.setMinAcceptablePacket((packet.seqNum + packet.payloadLength + 1));
				
				logEvent(null, client.currentTime, client.ip, "SEND SYN, \tDestination = " + server.ip , client.cssID);
				client.currentTime += packet.totalPacketSize/bandwidth ;
				if(topologyConfig == TopologyConfig.CLIENT_SERVER)
					server.currentTime += packet.totalPacketSize/bandwidth + rttDiv2;
				else{
					router.currentTime = client.currentTime + rtt1Div2 + switchingDelay;
					server.currentTime += packet.totalPacketSize/bandwidth + rtt1Div2 + switchingDelay + rtt2Div2;
				}
//				logEvent(null, server.currentTime, server.ip, "RECEIVE SYN, \tSource = " + client.ip );
				
			}
			else if(packet.SYN && packet.ACK){ // server sent a SYN-ACK to the client
				server.receiveCWnd.scale = packet.windowScale;
				int windowSize = (int)packet.scaledWindowSize;
//				int windowSize = (int)packet.windowSize;
				server.receiveCWnd.setMaxReceiveBufferSize((int)windowSize);
//				server.lastSeqNumSent = packet.seqNum;
//				server.lastAckNumSent = packet.ackNum;
//				server.sendCWnd.lastFrameSent = packet.seqNum + packet.headerLength + packet.payloadLength;
				server.sendCWnd.lastFrameSent = packet.seqNum + packet.payloadLength + 1;
//				server.sendCWnd.lastAckReceived = packet.seqNum + packet.headerLength + packet.payloadLength;
				server.sendCWnd.lastAckReceived = packet.seqNum + packet.payloadLength + 1;

				client.sendCWnd.scale = packet.windowScale;
//				client.sendCWnd.maxWndSize = windowSize;				
				client.sendCWnd.setMaxWndSize(windowSize);
				client.sendCWnd.receiverCurrentWndSize = windowSize; 
				//client.sendCWnd.currentCWndSize = packet.windowSize;
//				client.lastAckNumSent = packet.seqNum + packet.headerLength + packet.payloadLength;
//				client.receiveCWnd.setMinAcceptablePacket((packet.seqNum + packet.headerLength + packet.payloadLength));
				client.receiveCWnd.setMinAcceptablePacket((packet.seqNum + packet.payloadLength + 1));

				currentTime += packet.totalPacketSize/bandwidth + rttDiv2;
				logEvent(null, server.currentTime, server.ip, "RECEIVE SYN / SEND SYN-ACK, \tDestination = " + client.ip , server.cssID);
				server.currentTime += packet.totalPacketSize/bandwidth ;
				if(topologyConfig == TopologyConfig.CLIENT_SERVER)
					client.currentTime += packet.totalPacketSize/bandwidth + rtt;
				else{
					router.currentTime = server.currentTime + rtt2Div2 + switchingDelay;
//					client.currentTime += packet.totalPacketSize/bandwidth + rtt2Div2 + switchingDelay + rtt1Div2;					
					client.currentTime += packet.totalPacketSize/bandwidth + rtt2 + switchingDelay + rtt1;					
				}
				
//				logEvent(null, client.currentTime, client.ip, "RECEIVE SYN-ACK, \tSource= " + server.ip );
			}
			else if(packet.payloadLength <= 0){ // client sent a ACK to the server in response to SYN-ACK
				logEvent(null, client.currentTime, client.ip, "RECEIVE SYN-ACK / SEND ACK, \tDestination = " + server.ip , client.cssID);
				client.currentTime += packet.totalPacketSize/bandwidth ;
				
				if(topologyConfig == TopologyConfig.CLIENT_SERVER)
					server.currentTime += packet.totalPacketSize/bandwidth + rttDiv2;
				else{
					router.currentTime = client.currentTime + rtt1Div2 + switchingDelay;
					server.currentTime += packet.totalPacketSize/bandwidth + rtt1Div2 + switchingDelay + rtt2Div2;
				}
//				logEvent(null, server.currentTime, server.ip, "RECEIVE ACK, \tSource= " + client.ip , server.cssID);
			}
			else if(packet.payloadLength > 0){ 
				nextPacketIndx = i;
				if(packet.fromClient){
					TCPEvent event = new TCPEvent(EventType.SEND, flow.packets.get(nextPacketIndx), client.currentTime, server.ip, flow.flowNum, NodeType.CLIENT, NodeType.ROUTER, 0);
					event.packetIndx =nextPacketIndx ; 
					client.queueEvents.add(event);
				}
				else{
					TCPEvent event = new TCPEvent(EventType.SEND, flow.packets.get(nextPacketIndx), server.currentTime, client.ip, flow.flowNum, NodeType.SERVER, NodeType.ROUTER, 0);
					event.packetIndx =nextPacketIndx ; 
					server.queueEvents.add(event );
				}
				break;
			}
		}
		
		// todo: when sending if rec window size < packet size cannot send
		
//		currFlowPacketList.set(flow.flowNum, nextPacketIndx);
//		client.queueEvents.add(new TCPEvent(flow.packets.get(0), true, currentTime, client.ip, flow.flowNum));

//		client.queueEvents.add(new TCPEvent(EventType.RTT, rtt));
//		server.queueEvents.add(new TCPEvent(EventType.RTT, rtt));
		if(topologyConfig == TopologyConfig.CLIENT_SERVER){
		
			TCPEvent ec = client.queueEvents.peek();
			TCPEvent es = server.queueEvents.peek();
			while(!(ec == null && es == null)){
				if(ec == null){
					es = server.queueEvents.poll();
					ec = server.ProcessEvent(es);
					if(ec != null)		
						client.queueEvents.add(ec);
				}
				else if(es == null){
					ec = client.queueEvents.poll();
					es = client.ProcessEvent(ec);
					if(es != null)
						server.queueEvents.add(es);
				}
				else if(Double.max(ec.eventTime, client.currentTime)  < Double.max(es.eventTime, server.currentTime)){
					ec = client.queueEvents.poll();
					es = client.ProcessEvent(ec);
					if(es != null)
						server.queueEvents.add(es);
				}
				else{
					es = server.queueEvents.poll();
					ec = server.ProcessEvent(es);
					if(ec != null)
						client.queueEvents.add(ec);
				}
				
				ec = client.queueEvents.peek();
				es = server.queueEvents.peek();
			}
		}
		else{
			TCPEvent ec = client.queueEvents.peek();
			TCPEvent es = server.queueEvents.peek();
			TCPEvent er = router.queueEvents.peek();
			TCPEvent eventNew;
			while(!(ec == null && es == null && er == null)){
				double tc = Double.POSITIVE_INFINITY, ts = Double.POSITIVE_INFINITY, tr = Double.POSITIVE_INFINITY;
				if(ec != null)
					tc = Double.max(ec.eventTime, client.currentTime);
				if(es != null)
					ts = Double.max(es.eventTime, server.currentTime);
				if(er != null)
					tr = Double.max(er.eventTime, router.currentTime);
				if(tc <= ts && tc <= tr ){
						es = null;
						er = null;
				}
				else if(ts <= tc && ts <= tr ){
					ec = null;
					er = null;
				}
				else if(tr <= tc && tr <= ts ){
					ec = null;
					es = null;
				}
				if(es != null){
					es = server.queueEvents.poll();
					er = server.ProcessEvent(es);
					if(er != null)		
						router.queueEvents.add(er);
				}
				else if(ec != null){
					ec = client.queueEvents.poll();
					er = client.ProcessEvent(ec);
					if(er != null)
						router.queueEvents.add(er);
				}
				else if(er != null ){
					er = router.queueEvents.poll();
					eventNew = router.ProcessEvent(er);
					if(eventNew != null){
						if(eventNew.toNodeType == NodeType.CLIENT)
							client.queueEvents.add(eventNew);
						else
							server.queueEvents.add(eventNew);
					}
						
				}
				
				ec = client.queueEvents.peek();
				es = server.queueEvents.peek();
				er = router.queueEvents.peek();
			}
		}
		tcpStatistics.executionTime = client.currentTime;
		if(server.currentTime > tcpStatistics.executionTime )
			tcpStatistics.executionTime = server.currentTime ;
		if(router != null && router.currentTime > tcpStatistics.executionTime )
			tcpStatistics.executionTime = router.currentTime ;
		
		
	}
	
	public static double CalculatePacketReceiveTime(double currentTime, long packetSize, NodeType fromNode, NodeType toNode){
		if(topologyConfig == TopologyConfig.CLIENT_SERVER)
			return (double)(currentTime + rttDiv2 + packetSize/bandwidth);
		else if (topologyConfig == TopologyConfig.CLIENT_ROUTER_SERVER){
			if(fromNode == NodeType.CLIENT)
				return (double)(currentTime + rtt1Div2 + packetSize/bandwidth);
			if(fromNode == NodeType.SERVER)
				return (double)(currentTime + rtt2Div2 + packetSize/bandwidth);
			if(fromNode == NodeType.ROUTER){
				if(toNode == NodeType.CLIENT)
					return (double)(currentTime + rtt1Div2 + packetSize/bandwidth ); // switching delay is included by the router
				if(toNode == NodeType.SERVER)
					return (double)(currentTime + rtt2Div2 + packetSize/bandwidth );
			}
		}
		return 0;
	}

	public static double CalculatePacketRTOTime(double currentTime, long packetSize){
		return (double)(currentTime + rtt*2 + packetSize/bandwidth);
	}
	
	public static double CalculatePacketNextSendTime(double currentTime, long packetSize){
		return (double)(currentTime + packetSize/bandwidth);
	}

	// return index of next packet with payload
	// return -1 if no more payload packet
	public static int getNextPayloadIndx(int flowID, int currentPacketIndx){
		ArrayList<MyTCPPacket> packets = flowsList.get(flowID-1).packets;
		MyTCPPacket packetLast = packets.get(currentPacketIndx);
		for(int i=currentPacketIndx+1; i<packets.size(); i++){
			MyTCPPacket packet = packets.get(i);
			if(packet.payloadLength > 0 && packetLast.seqNum < packet.seqNum ){
				return i;
			}
		}
		return -1;
	}

	public static void logEvent(TCPEvent event, double currentTime, String endPointName, String text, String cssID){
		if(eventLogWriter == null){
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
			Date date = new Date();
			eventLogFilename = traceFilePath.substring(0, traceFilePath.length()-5) + "_eventsLog_" + dateFormat.format(date) + ".txt";
			eventLogFilename_css = traceFilePath.substring(0, traceFilePath.length()-5) + "_eventsLog_css_" + dateFormat.format(date) + ".txt";
			try {
				eventLogWriter = new PrintWriter(eventLogFilename);
				eventLogWriter_css = new PrintWriter(eventLogFilename_css);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			eventLogWriter.format("pcap file = %s\r\n", traceFilePath);
			eventLogWriter.format("Bandwidth (Kbps) = %s\r\n", bandwidth*8);
			eventLogWriter.format("Initial Congestion Window Size (MSS) = %s\r\n", initialCongWindowSize);
			eventLogWriter.format("Slow Start Threshold (MSS) = %s\r\n", slowStartThreshold);
			eventLogWriter.format("MSS (Bytes) = %s\r\n", MSS);
			if(topologyConfig == TopologyConfig.CLIENT_SERVER){
				eventLogWriter.format("LossRate = %s %%\r\n", lossRate*100);
				eventLogWriter.format("RTT (ms) = %s\r\n", rtt);
			}
			else{
				eventLogWriter.format("RTT1 (ms) = %s\r\n", rtt1);
				eventLogWriter.format("RTT2 (ms) = %s\r\n", rtt2);
				eventLogWriter.format("Switching Delay (PPS) = %s\r\n", 1/(switchingDelay/1000));
				eventLogWriter.format("Router Buffer Size (MSS) = %s\r\n", routerBufferSize);
			}
			eventLogWriter.format("\r\n\r\n");
		}
		String formattedText = "";
		if(event == null)
			formattedText = String.format("%-10.6f >>>> %-30s >>>> %s\r\n", currentTime ,endPointName, text);
//			eventLogWriter.format("%-10.6f >>>> %-30s >>>> %s\r\n", currentTime ,endPointName, text);
//		eventLogWriter.println(currentTime + "\t\t>>>>\t\t" + endPointName + "\t\t>>>>\t\t" + text);
		else
			formattedText = String.format("%-10.6f >>>> %-30s >>>> %-10s >>>> %s\r\n", currentTime ,endPointName, event.eventType.name(), text);
//			eventLogWriter.format("%-10.6f >>>> %-30s >>>> %-10s >>>> %s\r\n", currentTime ,endPointName, event.eventType.name(), text);
//			eventLogWriter.println(currentTime + "\t\t>>>>\t\t" + endPointName + "\t\t>>>>\t\t" + event.eventType.name() + "\t\t>>>>\t\t" + text);
		eventLogWriter.write(formattedText);
		eventLogWriter_css.write(formattedText);
		eventLogWriter_css.write(cssID + "\r\n");
//		eventLogWriter.println(text);		
		eventLogWriter.flush();
		eventLogWriter_css.flush();
//		try {
////			loqQ.add(new LogEvent(text, "sender"));
////			if(loqQ.size() >= maxlogQSize)
////				TCPSimulator.addEventLog(loqQ);
//
//			TCPSimulator.addEventLog(new LogEvent(formattedText , "sender"));
//				
////			TCPSimulator.addEventLogTest(text);
//		} catch (InterruptedException | ExecutionException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}

	public static void logCWndPerRTT(boolean isClient, long cwndSize, String endPointName, double currentTime){
		PrintWriter writer;
		if(isClient)
			writer = cwndLogWriter_client ;
		else
			writer = cwndLogWriter_server ;
		String filename;
		if(writer == null){
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
			Date date = new Date();
			filename = traceFilePath.substring(0, traceFilePath.length()-5) + "_cwndLog_" + endPointName + dateFormat.format(date) + ".txt";
			try {
				writer = new PrintWriter(filename);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if(isClient){
				cwndLogWriter_client = writer;
				cwndLogFilename_client = filename;
			}
			else{
				cwndLogWriter_server = writer;
				cwndLogFilename_server = filename;
			}
			String formattedText = "";
			formattedText = String.format("%s\r\n", 0);
			formattedText += String.format("%s\r\n", cwndSize);
			writer.write(formattedText);
			writer.flush();
			return;
		}
		long rttCount = 0;
		if(isClient && tcpStatistics.prevCwndSize_client != cwndSize){
			double timeDiff = currentTime - tcpStatistics.timeLastCwndRecorded_client;
			long RTTDiff = (long)(timeDiff/rtt);
			if(RTTDiff <= 0)
				return;
			tcpStatistics.rttCount_client += RTTDiff;
			rttCount = tcpStatistics.rttCount_client ;
			tcpStatistics.timeLastCwndRecorded_client = currentTime ;
			tcpStatistics.prevCwndSize_client = cwndSize;
		}
		else if(!isClient && tcpStatistics.prevCwndSize_server != cwndSize){
			double timeDiff = currentTime - tcpStatistics.timeLastCwndRecorded_server;
			long RTTDiff = (long)(timeDiff/rtt);
			if(RTTDiff <= 0)
				return;
			tcpStatistics.rttCount_server += RTTDiff;
			rttCount = tcpStatistics.rttCount_server ;
			tcpStatistics.timeLastCwndRecorded_server = currentTime ;
			tcpStatistics.prevCwndSize_server = cwndSize;
		}
		else
			return;
		
		String formattedText = "";
		formattedText = String.format("%s\r\n", rttCount);
		formattedText += String.format("%s\r\n", cwndSize);
		writer.write(formattedText);
		writer.flush();
		
//		if(isClient){
//			if(tcpStatistics.rttCount_client > 0 && tcpStatistics.prevCwndSize_client == cwndSize){
//				tcpStatistics.rttCount_client++;
//				return;
//			}
//			else{
//				tcpStatistics.rttCount_client++;
//				String formattedText = "";
//				formattedText = String.format("%s\r\n", tcpStatistics.rttCount_client);
//				formattedText += String.format("%s\r\n", cwndSize);
//				writer.write(formattedText);
//				writer.flush();
//				tcpStatistics.prevCwndSize_client = cwndSize;
//			}
//		}
//		else{
//			if(tcpStatistics.rttCount_server > 0 && tcpStatistics.prevCwndSize_server== cwndSize){
//				tcpStatistics.rttCount_server++;
//				return;
//			}
//			else{
//				tcpStatistics.rttCount_server++;
//				String formattedText = "";
//				formattedText = String.format("%s\r\n", tcpStatistics.rttCount_server);
//				formattedText += String.format("%s\r\n", cwndSize);
//				writer.write(formattedText);
//				writer.flush();
//				tcpStatistics.prevCwndSize_server = cwndSize;
//			}
//		}
	}

	public static void logPacketsInFlightPerRTT(boolean isClient, long cwndSize, String endPointName, double currentTime){
		logPacketsInFlightInTime(isClient, cwndSize, endPointName, currentTime);
		PrintWriter writer;
		if(isClient)
			writer = inflightLogWriter_client ;
		else
			writer = inflightLogWriter_server ;
		String filename;
		if(writer == null){
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
			Date date = new Date();
			filename = traceFilePath.substring(0, traceFilePath.length()-5) + "_inflightLog_" + endPointName + dateFormat.format(date) + ".txt";
			try {
				writer = new PrintWriter(filename);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if(isClient){
				inflightLogWriter_client = writer;
				inflightLogFilename_client = filename;
			}
			else{
				inflightLogWriter_server = writer;
				inflightLogFilename_server = filename;
			}
			String formattedText = "";
			formattedText = String.format("%s\r\n", 0);
			formattedText += String.format("%s\r\n", cwndSize);
			writer.write(formattedText);
			writer.flush();
			return;
		}
		int x = 0;
		if(cwndSize < 0)
			x++;
		long rttCount = 0;
		if(isClient && tcpStatistics.prevInflightSize_client != cwndSize){
			double timeDiff = currentTime - tcpStatistics.timeLastInflightRecorded_client;
			long RTTDiff = (long)(timeDiff/rtt);
			if(RTTDiff <= 0)
				return;
			tcpStatistics.rttCountInflight_client += RTTDiff;
			rttCount = tcpStatistics.rttCountInflight_client ;
			tcpStatistics.timeLastInflightRecorded_client = currentTime ;
			tcpStatistics.prevInflightSize_client = cwndSize;
		}
		else if(!isClient && tcpStatistics.prevInflightSize_server != cwndSize){
			double timeDiff = currentTime - tcpStatistics.timeLastInflightRecorded_server;
			long RTTDiff = (long)(timeDiff/rtt);
			if(RTTDiff <= 0)
				return;
			tcpStatistics.rttCountInflight_server += RTTDiff;
			rttCount = tcpStatistics.rttCountInflight_server ;
			tcpStatistics.timeLastInflightRecorded_server = currentTime ;
			tcpStatistics.prevInflightSize_server = cwndSize;
		}
		else
			return;
		
		String formattedText = "";
		formattedText = String.format("%s\r\n", rttCount);
		formattedText += String.format("%s\r\n", cwndSize);
		writer.write(formattedText);
		writer.flush();
		
	}

	public static void logPacketsInFlightInTime(boolean isClient, long cwndSize, String endPointName, double currentTime){
		PrintWriter writer;
		if(isClient)
			writer = inflightTimeLogWriter_client ;
		else
			writer = inflightTimeLogWriter_server ;
		String filename;
		if(writer == null){
			DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
			Date date = new Date();
			filename = traceFilePath.substring(0, traceFilePath.length()-5) + "_inflightTimeLog_" + endPointName + dateFormat.format(date) + ".txt";
			try {
				writer = new PrintWriter(filename);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if(isClient){
				inflightTimeLogWriter_client = writer;
				inflightTimeLogFilename_client = filename;
			}
			else{
				inflightTimeLogWriter_server = writer;
				inflightTimeLogFilename_server = filename;
			}
			String formattedText = "";
			formattedText = String.format("%s\r\n", 0);
			formattedText += String.format("%s\r\n", cwndSize);
			writer.write(formattedText);
			writer.flush();
			return;
		}
		int x = 0;
		if(cwndSize < 0)
			x++;
		long rttCount = 0;
		if(isClient && tcpStatistics.prevInflightTimeSize_client != cwndSize){
			if(tcpStatistics.prevInflightTimeSize_client  - cwndSize > 10 )
				x++;
			double timeDiff = currentTime - tcpStatistics.timeLastInflightTimeRecorded_client;
			long RTTDiff = (long)(timeDiff/rtt_original);
			if(RTTDiff <= 0)
				return;
			tcpStatistics.rttCountInflightTime_client += RTTDiff;
			rttCount = tcpStatistics.rttCountInflightTime_client ;
			tcpStatistics.timeLastInflightTimeRecorded_client = currentTime ;
			tcpStatistics.prevInflightTimeSize_client = cwndSize;
		}
		else if(!isClient && tcpStatistics.prevInflightTimeSize_server != cwndSize){
			double timeDiff = currentTime - tcpStatistics.timeLastInflightTimeRecorded_server;
			long RTTDiff = (long)(timeDiff/rtt_original);
			if(RTTDiff <= 0)
				return;
			tcpStatistics.rttCountInflightTime_server += RTTDiff;
			rttCount = tcpStatistics.rttCountInflightTime_server ;
			tcpStatistics.timeLastInflightTimeRecorded_server = currentTime ;
			tcpStatistics.prevInflightTimeSize_server = cwndSize;
		}
		else
			return;
		
		String formattedText = "";
		formattedText = String.format("%s\r\n", rttCount);
		formattedText += String.format("%s\r\n", cwndSize);
		writer.write(formattedText);
		writer.flush();
		
	}
}
