/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

import java.util.ArrayList;

public class MyTCPFlow {
	public static int maxFlowNum = 0;	
	
	byte[] srcIP, destIP;
	String srcIP_str = "", destIP_str = "";
	long srcPort = 0, destPort = 0;
	boolean Fin = false;
	long windowScaleSrc = 0;
	long windowScaleDest = 0;
			
	int flowNum = 0;
	long packetCountFromSrc = 0, packetCountFromDest = 0;
	long packetCount = 0; 
	long packetCountFromSrc_Retransmitted = 0; 
	long totalDataBytes_srcToDest = 0;
	long totalDataBytes_destToSrc = 0;
	long startTS_srcToDest = 0, endTS_srcToDest = 0;
	long startTS_destToSrc = 0, endTS_destToSrc = 0;
	long start_captureTS_ms = 0, end_captureTS_ms  = 0;
	double lossRate = 0;
	double avgRTT = 0;
	int MSS = 0;
	
	ArrayList<MyTCPPacket> packets = new ArrayList<MyTCPPacket>(); 
	ArrayList<MyTCPPacket> packetsSent = new ArrayList<MyTCPPacket>(); 
	ArrayList<MyTCPPacket> packetsReceived = new ArrayList<MyTCPPacket>(); 

	public MyTCPFlow(){
		maxFlowNum ++;
		flowNum =maxFlowNum ; 
	}
	public String toString(){
		return "Src IP = " + srcIP_str 
				+ ", \tDest IP = " + destIP_str 
				+ ", \tSrc Port = " + srcPort 
				+ ", \tDest Port = " + destPort 
				+ "\n";
	}

}
