/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

import java.util.ArrayList;

public class TCPStatistics {
	double executionTime = 0;
	long totalPacketsSent = 0;
	long lostPacketsCount = 0;
	long lostAcksCount = 0;
	long lostTotalCount = 0;
	long retransmissionsCount = 0;
	long timeoutCount = 0;
	long timeoutCount_eff = 0;
	long tripleDupAckCount = 0;
	double totalSampleRTT = 0;
	long SampleRTTCount = 0;
	double averageRTT = 0;
//	ArrayList<Long> cwndSizePerRTT_client = new ArrayList<Long>();  
//	ArrayList<Long> cwndSizePerRTT_server = new ArrayList<Long>();
	long prevCwndSize_client = 0;
	long rttCount_client = 0;
	long prevCwndSize_server = 0;
	long rttCount_server = 0;
	double timeLastCwndRecorded_client = 0; 
	double timeLastCwndRecorded_server = 0; 
	long prevInflightSize_client = 0;
	long rttCountInflight_client = 0;
	long prevInflightSize_server = 0;
	long rttCountInflight_server = 0;
	double timeLastInflightRecorded_client = 0; 
	double timeLastInflightRecorded_server = 0; 
	long prevInflightTimeSize_client = 0;
	long prevInflightTimeSize_server = 0;
	double timeLastInflightTimeRecorded_client = 0; 
	double timeLastInflightTimeRecorded_server = 0; 
	long rttCountInflightTime_client = 0;
	long rttCountInflightTime_server = 0;
	
}
