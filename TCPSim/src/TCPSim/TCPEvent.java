/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

import java.util.Comparator;

public class TCPEvent implements Comparator<TCPEvent>, Comparable<TCPEvent>{
	EventType eventType;
	MyTCPPacket packet;
	//boolean isSending = true;
	double eventTime = 0;
	String targetEndPoint = "";
	int flowID = 0;
	int packetIndx;
	NodeType fromNodeType;
	NodeType toNodeType;
	double sendingTime = 0;
	
	
	// handler end point
	// next handler
	// time
//	public TCPEvent(EventType eventType, MyTCPPacket packet, double eventTime, String targetEndPoint, int flowID){
//		this.eventType = eventType;
//		this.packet = packet;
//		//this.isSending = isSending;
//		this.eventTime = eventTime;
//		this.targetEndPoint = targetEndPoint;
//		this.flowID = flowID;
//	}
	
	public TCPEvent(EventType eventType, MyTCPPacket packet, double eventTime, String targetEndPoint, int flowID, NodeType fromNodeType , NodeType toNodeType, double sendingTime ){
		this.eventType = eventType;
		this.packet = packet;
		//this.isSending = isSending;
		this.eventTime = eventTime;
		this.targetEndPoint = targetEndPoint;
		this.flowID = flowID;
		this.fromNodeType = fromNodeType;
		this.toNodeType = toNodeType;
		this.sendingTime = sendingTime;
	}

	public TCPEvent(EventType eventType, double eventTime){
		this.eventType = eventType;
		this.eventTime = eventTime;
	}

	public int compare(TCPEvent x, TCPEvent y)
    {
        if (x.eventTime < y.eventTime)
        {
            return -1;
        }
        if (x.eventTime > y.eventTime)
        {
            return 1;
        }
        if(x.eventType == y.eventType 
        		&& x.flowID == y.flowID
        		&& ((x.eventType != EventType.ACK && x.packet.seqNum == y.packet.seqNum)
        				|| (x.eventType == EventType.ACK && x.packet.ackNum == y.packet.ackNum)))
        		return 0;
        return 1;
    }

	@Override
	public int compareTo(TCPEvent o) {
        if (this.eventTime < o.eventTime)
        {
            return -1;
        }
        if (this.eventTime > o.eventTime)
        {
            return 1;
        }
        return 0;
	}

}
