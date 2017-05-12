/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

public enum CWndUpdateEventType {
	INITIALIZE,
	ACK,
	TRIPLE_DUPLICATE_ACK,
	TIMEOUT,

}
