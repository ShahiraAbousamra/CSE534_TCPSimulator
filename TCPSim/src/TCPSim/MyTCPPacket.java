/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

public class MyTCPPacket {
	int resendCount = 0;
	// Main TCP Header fields
	long srcPort = 0, destPort = 0, dataOffset = 0, windowSize = 0;
	long seqNum = 0, ackNum = 0; 
	boolean NS = false, CWR = false, ECE = false, URG = false, ACK = false, PSH = false, RST = false, SYN = false, FIN = false;

	// TCP Optional Header fields	
	int MSS = 0;
	int windowScale = 0;
	long scaledWindowSize = 0; 
	boolean selectiveAck = false;
	long[] selectiveAckFrom, selectiveAckTo;
	long senderTS = 0, echoReceivedTS = 0;
	long captureTS_ms = 0;
	
	byte[] tcpPayload = null;
	
	// Other Fields
	byte[] srcIP, destIP;
	String srcIP_str = "", destIP_str = "";
	int flowID = 0;
	long packetNumber = 0;
	int headerLength = 0, payloadLength = 0;	
	boolean fromClient = true;
	long totalPacketSize = 0;
	
	
	public String toString(){
		return "Flow ID = " + flowID 
				+ "\t Source = " + srcIP_str
				+ "\t Destination = " + destIP_str
				+ "\t Packet Number = " + packetNumber
				+ "\t Source Port = " + srcPort
				+ "\t Destination Port = " + destPort
				+ "\t Sequence Number = " + seqNum
				+ "\t Acknowledgment Number = " + ackNum
				+ "\t WindowSize = " + windowSize
				+ "\t Flags = "
				+ (SYN?" SYN ": "")
				+ (ACK?" ACK ": "")
				+ (FIN?" FIN ": "")
				+ (PSH?" PSH": "")
				+ (RST?" RST": "")
				+ (URG?" URG": "")
				+ (NS?" NS": "")
				+ (CWR?" CWR ": "")
				+ (ECE?" ECE ": "")
				+ (selectiveAck?" Selective Ack ": "")				
				+ "\r\n"
				;
	
	}
}
