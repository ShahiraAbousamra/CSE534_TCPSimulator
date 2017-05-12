/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;


import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Queue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

import javax.xml.stream.util.StreamReaderDelegate;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.Border;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.BorderStroke;
import javafx.scene.layout.BorderStrokeStyle;
import javafx.scene.layout.BorderWidths;
import javafx.scene.layout.CornerRadii;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.Text;
import javafx.scene.text.TextFlow;
import javafx.stage.FileChooser;
import javafx.stage.Modality;
import javafx.stage.Stage;

public class TCPSimulator extends Application {

	File file = null;
	TCPCoordinator tcpCoordinator = new TCPCoordinator();
	public static TextFlow flowEvents = null; 
	public static TextFlow flowStats = null; 
	public static ScrollPane scrollEvents = null;
	RandomAccessFile raf = null; 
	ArrayList<Long> offsetList = null;	
	int nLines = 100;
	boolean isEOF = false;
	int currentOffsetIndx = -1;
	Stage primaryStage;
	
	@Override
	public void start(Stage primaryStage) {
		this.primaryStage = primaryStage;
		primaryStage.setTitle("TCP Simulator");
		BorderPane p = new BorderPane();
		Text t = new Text("Hello FX");
		t.setFont(Font.font("Arial", 60));
		t.setEffect(new DropShadow(2, 3, 3, Color.RED));
//		p.setTop(t);
		
		GridPane gridPane = new GridPane();
		gridPane.setHgap(10);
		gridPane.setVgap(10);
		gridPane.setPadding(new Insets(15, 12, 15, 12));
		int currentRow = 0;
		int currentCol = 0;

		final Label lblPcapFile = new Label("PCap File:");
		final TextField txtPcapFile = new TextField();
		txtPcapFile.setPrefColumnCount(40);
		final FileChooser fileChooser = new FileChooser();
		final Button btnSelectFile = new Button("Select File"/*, new ImageView("image/left.gif")*/);
		currentCol = 0;
		gridPane.add(lblPcapFile, currentCol++, currentRow);
		int colSpan = 2;
		gridPane.add(txtPcapFile, currentCol, currentRow, colSpan, 1);
		currentCol += colSpan;
		gridPane.add(btnSelectFile, currentCol++, currentRow);
		currentRow++;
		
		final Label lblTopology = new Label("Topology:");
		final ToggleGroup rdGrpTopology = new ToggleGroup();
		final RadioButton rdClientServer = new RadioButton("Client - Server");
		rdClientServer.setToggleGroup(rdGrpTopology);
		final RadioButton rdClientRouterServer = new RadioButton("Client - Router - Server");
		rdClientRouterServer.setToggleGroup(rdGrpTopology);
		currentCol = 0;
		gridPane.add(lblTopology, currentCol++, currentRow);
		gridPane.add(rdClientServer, currentCol++, currentRow);
		gridPane.add(rdClientRouterServer, currentCol++, currentRow);
		currentRow++;


		GridPane subGridPane1 = new GridPane();
		subGridPane1.setHgap(10);
		subGridPane1.setVgap(10);
		subGridPane1.setPadding(new Insets(15, 12, 15, 12));
		subGridPane1.setAlignment(Pos.TOP_LEFT);
		int subGridPane1_currentRow = 0;
		int subGridPane1_currentCol = 0;
		currentCol = 0;
		colSpan = 4;
		gridPane.add(subGridPane1, currentCol, currentRow, colSpan, 1);


		

		

		final Label lblBandwidth = new Label("Bandwidth:");
		final TextField txtBandwidth = new TextField();
		final Label lblBandwidthUnits = new Label("Kbps");
		subGridPane1_currentCol = 0;
		subGridPane1.add(lblBandwidth, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(txtBandwidth, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(lblBandwidthUnits, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1_currentRow++;

		
		final Label lblMSS = new Label("MSS:");
		final TextField txtMSS = new TextField();
		final Label lblMSSUnits = new Label("Bytes");
		subGridPane1_currentCol = 0;
		subGridPane1.add(lblMSS, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(txtMSS, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(lblMSSUnits, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1_currentRow++;
		
		final Label lblInitialCWndSize = new Label("Initial CWnd Size:");
		final TextField txtInitialCWndSize= new TextField();
		final Label lblInitialCWndSizeUnits = new Label("MSS");
		subGridPane1_currentCol = 0;
		subGridPane1.add(lblInitialCWndSize, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(txtInitialCWndSize, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(lblInitialCWndSizeUnits, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1_currentRow++;
		
		final Label lblSlowStartThreshold = new Label("Slow Start Threshold:");
		final TextField txtSlowStartThreshold= new TextField();
		final Label lblSlowStartThresholdUnits = new Label("MSS");
		subGridPane1_currentCol = 0;
		subGridPane1.add(lblSlowStartThreshold, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(txtSlowStartThreshold, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1.add(lblSlowStartThresholdUnits, subGridPane1_currentCol++, subGridPane1_currentRow);
		subGridPane1_currentRow++;
		
		
		final Label lblRTT = new Label("RTT:");
		final TextField txtRTT = new TextField();
		final Label lblRTTUnits = new Label("ms");

		final Label lblRTT1 = new Label("RTT1 (Client - Router):");
		final TextField txtRTT1 = new TextField();
		final Label lblRTTUnits1 = new Label("ms");

		final Label lblRTT2 = new Label("RTT2 (Router - Server):");
		final TextField txtRTT2 = new TextField();
		final Label lblRTTUnits2 = new Label("ms");

		// Add to Sub Grid 1
		GridPane subGridPane3 = new GridPane();
		subGridPane3.setHgap(10);
		subGridPane3.setVgap(10);
//		subGridPane3.setPadding(new Insets(15, 12, 15, 12));
		int subGridPane3_currentRow = 0;
		int subGridPane3_currentCol = 0;
		currentCol = 0;
		colSpan = 4;
		subGridPane1_currentCol = 0;
		subGridPane1.add(subGridPane3, subGridPane1_currentCol, subGridPane1_currentRow , colSpan, 1);
//		subGridPane1_currentRow++;
		subGridPane3.add(lblRTT, subGridPane3_currentCol++, subGridPane3_currentRow);
		subGridPane3.add(txtRTT, subGridPane3_currentCol++, subGridPane3_currentRow);
		subGridPane3.add(lblRTTUnits, subGridPane3_currentCol++, subGridPane3_currentRow);
		subGridPane3_currentRow++;

		final Label lblLossRate = new Label("Loss Rate:");
		final TextField txtLossRate= new TextField();
		final Label lblLossRateUnits = new Label("%");
		subGridPane3_currentCol = 0;
		subGridPane3.add(lblLossRate, subGridPane3_currentCol++, subGridPane3_currentRow);
		subGridPane3.add(txtLossRate, subGridPane3_currentCol++, subGridPane3_currentRow);
		subGridPane3.add(lblLossRateUnits, subGridPane3_currentCol++, subGridPane3_currentRow);
		subGridPane3_currentRow++;
		

		GridPane subGridPane2 = new GridPane();
		subGridPane2.setHgap(10);
		subGridPane2.setVgap(10);
//		subGridPane2.setPadding(new Insets(15, 12, 15, 12));
		int subGridPane2_currentRow = 0;
		int subGridPane2_currentCol = 0;
		currentCol = 0;
		colSpan = 4;
		subGridPane1_currentCol = 0;
		subGridPane1.add(subGridPane2, subGridPane1_currentCol, subGridPane1_currentRow , colSpan, 1);
		subGridPane1_currentRow++;

		subGridPane2_currentCol = 0;
		subGridPane2.add(lblRTT1, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(txtRTT1, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(lblRTTUnits1, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(lblRTT2, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(txtRTT2, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(lblRTTUnits2, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2_currentRow++;

		final Label lblSwitchingDelay = new Label("Router Switching Speed:");
		final TextField txtSwitchingDelay = new TextField();
		final Label lblSwitchingDelayUnits = new Label("PPS");
		subGridPane2_currentCol = 0;
		subGridPane2.add(lblSwitchingDelay, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(txtSwitchingDelay, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(lblSwitchingDelayUnits, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2_currentRow++;

		final Label lblMaxBufferSize = new Label("Router Max Buffer Size:");
		final TextField txtMaxBufferSize = new TextField();
		final Label lblMaxBufferSizeUnits = new Label("MSS");
		subGridPane2_currentCol = 0;
		subGridPane2.add(lblMaxBufferSize, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(txtMaxBufferSize, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2.add(lblMaxBufferSizeUnits, subGridPane2_currentCol++, subGridPane2_currentRow);
		subGridPane2_currentRow++;

		// statistics
		VBox vb_stats = new VBox();
		vb_stats.setPadding(new Insets(15, 12, 15, 12));
		Label lblStats = new Label("Statistics:");
		lblStats.setId("statsTitle");
	    vb_stats.getChildren().add(lblStats);
		flowStats = new TextFlow();
		flowStats.setId("stats");
		flowStats.setPrefHeight(10);
	    vb_stats.getChildren().add(flowStats);
		ScrollPane scrollStats = new ScrollPane();
		scrollStats.setContent(vb_stats);
		scrollStats.setPrefHeight(300);
		scrollStats.setId("stats"); 

		// Events
		VBox vb_sub = new VBox();
		flowEvents = new TextFlow();
	    flowEvents.setId("events");
	    flowEvents.setPrefHeight(10);
		vb_sub.getChildren().add(flowEvents);
		scrollEvents = new ScrollPane();
		scrollEvents.setContent(vb_sub);
		scrollEvents.setPrefHeight(300);
		scrollEvents.setPrefWidth(500);
		scrollEvents.setId("events");

		final Button btnProcessFile = new Button("Process File"/*, new ImageView("image/left.gif")*/);
		HBox hbButtons = new HBox();
		hbButtons.getChildren().add(btnProcessFile);
		hbButtons.setSpacing(10);
		hbButtons.setAlignment(Pos.CENTER);

		final Button btnEventsViewerPrev = new Button("Prev");
		final Button btnEventsViewerNext = new Button("Next");
		HBox hbEventsViewer = new HBox();
		hbEventsViewer.getChildren().add(btnEventsViewerPrev);
		hbEventsViewer.getChildren().add(btnEventsViewerNext);
		hbEventsViewer.setSpacing(10);
		hbEventsViewer.setAlignment(Pos.CENTER);

		VBox vb = new VBox();
		vb.setPadding(new Insets(15, 12, 15, 12));
		vb.getChildren().add(gridPane);
		vb.getChildren().add(hbButtons);
		vb.getChildren().add(scrollStats);
		vb.getChildren().add(scrollEvents);
		vb.getChildren().add(hbEventsViewer);		
		vb.getChildren().add(new Label(""));
		vb.setSpacing(10);

		ScrollPane scrollpane = new ScrollPane();
		scrollpane.setContent(vb);
//		p.setCenter(vb);
		p.setCenter(scrollpane);

		// default values
		txtPcapFile.setText("C:\\Data\\CSE 534 - Networks\\Spring 2017\\Project\\assignment2.pcap");
//		txtPcapFile.setText("C:\\Data\\CSE 534 - Networks\\Spring 2017\\Project\\tcp_8094.pcap");
		rdClientServer.setSelected(true);
		subGridPane3.setVisible(true);
//		hbRouter.setVisible(false);
		subGridPane2.setVisible(false);
		txtRTT.setText("73");
		txtRTT1.setText("36");
		txtRTT2.setText("36");
		txtSwitchingDelay.setText("20000");
		txtBandwidth.setText("20000");
		txtMSS.setText("1480");
		txtInitialCWndSize.setText("10");
		txtSlowStartThreshold.setText("300");
		txtLossRate.setText("0");
		txtMaxBufferSize.setText("200");
		scrollStats.setVisible(false);
		scrollEvents.setVisible(false);
		hbEventsViewer.setVisible(false);
		 
		//p.setBottom(btnSelectFile);
		btnSelectFile.setOnAction(e -> {
			try {
				//new analysis_pcap_tcp().AnalyzeFile(txtPcapFile.getText());
				file = fileChooser.showOpenDialog(primaryStage);
                if (file != null) {
                    //openFile(file);
                	txtPcapFile.setText(file.getAbsolutePath());
                }
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});
		
		rdClientServer.setOnAction(e -> {
			try {
				subGridPane3.setVisible(true);
				subGridPane2.setVisible(false);

			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
		});

		rdClientRouterServer.setOnAction(e -> {
			try {

				subGridPane3.setVisible(false);
				subGridPane2.setVisible(true);


			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			
		});

		// button to start simulation
		btnProcessFile.setOnAction(e -> {
			try {
				if(raf != null){
					raf.close();
					raf = null;
				}
				scrollStats.setVisible(false);
				scrollEvents.setVisible(false);
				hbEventsViewer.setVisible(false);
				String errorMsgs = "";
				// Validate input
				String rtt_str = txtRTT.getText().trim();
				long rtt = 0;
				String rtt1_str = txtRTT1.getText().trim();
				long rtt1 = 0;
				String rtt2_str = txtRTT2.getText().trim();
				long rtt2 = 0;
				String switchingDelay_str = txtSwitchingDelay.getText().trim();
				double switchingDelay = 0;
				String bufferSize_str = txtMaxBufferSize.getText().trim();
				int bufferSize= 0;
				String bandwidth_str = txtBandwidth.getText().trim();
				double bandwidth = 0;
				String mss_str = txtMSS.getText().trim();
				int mss = 0;
				String initCWnd_str = txtInitialCWndSize.getText().trim();
				int initCWnd = 0;
				String ssThreshold_str = txtSlowStartThreshold.getText().trim();
				int ssThreshold = 0;
				String lossRate_str = txtLossRate.getText().trim();
				double lossRate = 0;
				// Parse RTT
				if(rdClientServer.isSelected()){
					if(rtt_str.isEmpty()){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "RTT Value is Missing";
					}
					else{
						try{
							rtt = Long.parseLong(rtt_str);						
						}
						catch(Exception ex){
							errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
							errorMsgs += "RTT value is not valid";						
						}
					}					
				}
				if(rdClientRouterServer.isSelected()){
					// Parse RTT 1 (Client - Router)
					if(rtt1_str.isEmpty()){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "RTT1 (Client - Router) Value is Missing";
					}
					else{
						try{
							rtt1 = Long.parseLong(rtt1_str);						
						}
						catch(Exception ex){
							errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
							errorMsgs += "RTT1 (Client - Router) value is not valid";						
						}
					}					
					// Parse RTT 2 (Router - Server)
					if(rtt1_str.isEmpty()){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "RTT2 (Router - Server) Value is Missing";
					}
					else{
						try{
							rtt2 = Long.parseLong(rtt2_str);						
						}
						catch(Exception ex){
							errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
							errorMsgs += "RTT2 (Router - Server) value is not valid";						
						}
					}					
					// Parse Switching Delay
					if(switchingDelay_str.isEmpty()){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "Switching Speed Value is Missing";
					}
					else{
						try{
							switchingDelay = Double.parseDouble(switchingDelay_str);						
						}
						catch(Exception ex){
							errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
							errorMsgs += "Switching Speed value is not valid";						
						}
					}					
					// Parse Max Buffer Size
					if(bufferSize_str.isEmpty()){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "Max Buffer Size Value is Missing";
					}
					else{
						try{
							bufferSize = Integer.parseInt(bufferSize_str);						
						}
						catch(Exception ex){
							errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
							errorMsgs += "Max Buffer Size value is not valid";						
						}
					}					
				}
				// Parse Bandwidth
				if(bandwidth_str.isEmpty()){
					errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
					errorMsgs += "Bandwidth Value is Missing";
				}
				else{
					try{
						bandwidth = Double.parseDouble(bandwidth_str);						
					}
					catch(Exception ex){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "Bandwidth value is not valid";						
					}
				}					
				// Parse Filename
				if (txtPcapFile.getText().trim().isEmpty()) {
					errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
					errorMsgs += "PCAP file is Missing";			
				}
				// Parse MSS
				if(mss_str.isEmpty()){
					errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
					errorMsgs += "MSS Value is Missing";
				}
				else{
					try{
						mss = Integer.parseInt(mss_str);						
					}
					catch(Exception ex){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "MSS value is not valid";						
					}
				}					
				// Parse Initial CWnd Size
				if(initCWnd_str.isEmpty()){
					errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
					errorMsgs += "Initial CWnd Size is Missing";
				}
				else{
					try{
						initCWnd = Integer.parseInt(initCWnd_str);						
					}
					catch(Exception ex){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "Initial CWnd Size is not valid";						
					}
				}					
				// Parse Slow Start Threshold
				if(ssThreshold_str.isEmpty()){
					errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
					errorMsgs += "Slow Start Threshold is Missing";
				}
				else{
					try{
						ssThreshold = Integer.parseInt(ssThreshold_str);						
					}
					catch(Exception ex){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "Slow Start Threshold is not valid";						
					}
				}					
				
				// Parse Loss Rate
				if(lossRate_str.isEmpty()){
					errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
					errorMsgs += "Loss Rate is Missing";
				}
				else{
					try{
						lossRate = Double.parseDouble(lossRate_str);						
					}
					catch(Exception ex){
						errorMsgs += errorMsgs.isEmpty()?"":"\r\n";
						errorMsgs += "Loss Rate is not valid";						
					}
				}					
                if (!errorMsgs.isEmpty()) {
                	Alert alert = new Alert(AlertType.ERROR);
                	alert.setTitle("Input Validation");
                	alert.setHeaderText(errorMsgs);
                	//alert.setContentText(errorMsgs);

                	alert.showAndWait();
                	return;
                	
                }
                if(rdClientServer.isSelected())
                	TCPCoordinator.setConfig(TopologyConfig.CLIENT_SERVER, rtt, bandwidth, mss, initCWnd, ssThreshold, lossRate); ///////////
                else
                	TCPCoordinator.setConfig(TopologyConfig.CLIENT_ROUTER_SERVER, rtt1, rtt2, switchingDelay, bandwidth, mss, initCWnd, ssThreshold, bufferSize); ///////////
                
            	TCPCoordinator.useFile(txtPcapFile.getText().trim());
            	Alert alert = new Alert(AlertType.INFORMATION);
            	alert.setTitle("Status");
            	alert.setHeaderText("Done!");
            	alert.showAndWait();
            	TCPCoordinator.eventLogWriter.close();
            	TCPCoordinator.eventLogWriter_css.close();
            	TCPCoordinator.cwndLogWriter_client.close();
            	TCPCoordinator.cwndLogWriter_server.close();
        		scrollStats.setVisible(true);
        		scrollEvents.setVisible(true);
        		hbEventsViewer.setVisible(true);
        		TCPCoordinator.tcpStatistics.averageRTT = TCPCoordinator.tcpStatistics.totalSampleRTT/(double)TCPCoordinator.tcpStatistics.SampleRTTCount;
        		showStats(TCPCoordinator.tcpStatistics);
            	showNext();
            	showChart();
            	showChartInflight();
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});

		// button Events Viewer Next
		btnEventsViewerNext.setOnAction(e -> {
			try {
				showNext();

			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});

		// button Events Viewer Prev
		btnEventsViewerPrev.setOnAction(e -> {
			try {
				showPrev();

			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		});

		Scene scene = new Scene(p);
		try{
			scene.getStylesheets().add(getClass().getResource("../styles.css").toExternalForm());
		}
		catch(Exception e){
			// used to handle loading css from jar
			Path currentRelativePath = Paths.get("");
			String s = "file:///" + currentRelativePath.toAbsolutePath().toString() + "/styles.css";
			s = s.replace("\\", "/");
			s = s.replace(" ", "%20");
			System.out.println(s);
			scene.getStylesheets().add(s);
		}
//		scene.getStylesheets().add(getClass().getResource("./styles.css").toExternalForm());
		
		primaryStage.setScene(scene);
		primaryStage.setMaximized(true); //setFullScreen(true);
		primaryStage.show();
	}

	public static void main(String[] args) {
		launch(args);
	}
	
	
	public static void addEventLog(LogEvent logEvent) throws InterruptedException, ExecutionException {

	    // actual work to update UI:
	    FutureTask<Void> updateUITask = new FutureTask(() -> {

			Text txt = new Text(logEvent.description);
			txt.setId(logEvent.cssID);
			flowEvents.getChildren().add(txt);

	    }, /* return value from task: */ null);

	    // submit for execution on FX Application Thread:
	    Platform.runLater(updateUITask);

	    // block until work complete:
	    updateUITask.get();
	}
	
	public static void addEventLog(Queue<LogEvent> logEventQ) throws InterruptedException, ExecutionException {

	    // actual work to update UI:
	    FutureTask<Void> updateUITask = new FutureTask(() -> {
	    	while(logEventQ.peek() != null){
	    		LogEvent logEvent = logEventQ.poll();    
				Text txt = new Text(logEvent.description+"\r\n");
				txt.setId(logEvent.cssID);
				flowEvents.getChildren().add(txt);
	    	}

	    }, /* return value from task: */ null);

	    // submit for execution on FX Application Thread:
	    Platform.runLater(updateUITask);

	    // block until work complete:
	    updateUITask.get();
	}

	public static void addEventLogTest(String str) throws InterruptedException, ExecutionException {


			Text txt = new Text(str+"\r\n");
			txt.setId("sender");
			flowEvents.getChildren().add(txt);

	}

	public void showNext() {
		try {
//			FileInputStream fs = new FileInputStream(TCPCoordinator.eventLogFilename);
//			BufferedReader br = new BufferedReader(new FileReader(new File(TCPCoordinator.eventLogFilename)));
			if(raf == null){
				raf =  new RandomAccessFile(TCPCoordinator.eventLogFilename_css, "r");
				offsetList = new ArrayList<Long>();
				isEOF = false;
				currentOffsetIndx = 0;
				offsetList.add(((long)0));
				flowEvents.getChildren().clear();
			}
			else{
				if(isEOF)
					return;
				else if(!isEOF){
					if(currentOffsetIndx == offsetList.size()-1){
						try {
							offsetList.add(raf.getFilePointer());
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					currentOffsetIndx++;
				}
			}
				
			int readLines  = 0;			
			if(!isEOF)
				flowEvents.getChildren().clear();
			while(readLines < nLines && !isEOF){
				try {
					String str = raf.readLine();
					Text txt = new Text(str+"\r\n");
					str = raf.readLine();
					txt.setId(str);
					flowEvents.getChildren().add(txt);
					readLines++;
				} 
				catch (EOFException e) {
					isEOF = true;
					// TODO Auto-generated catch block
//					e.printStackTrace();
				}
				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			scrollEvents.setVvalue(0);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}


	public void showPrev() {
		try {
//			FileInputStream fs = new FileInputStream(TCPCoordinator.eventLogFilename);
//			BufferedReader br = new BufferedReader(new FileReader(new File(TCPCoordinator.eventLogFilename)));
			if(raf == null){
				return;
			}
			
			if(currentOffsetIndx <= 0)
				return;
			currentOffsetIndx--;
			isEOF = false;
				
			try {
				raf.seek(offsetList.get(currentOffsetIndx));
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			int readLines  = 0;			
			flowEvents.getChildren().clear();
			while(readLines < nLines && !isEOF){
				try {
					String str = raf.readLine();
					Text txt = new Text(str+"\r\n");
					str = raf.readLine();
					txt.setId(str);
					flowEvents.getChildren().add(txt);
					readLines++;
				} 
				catch (EOFException e) {
					isEOF = true;
					// TODO Auto-generated catch block
//					e.printStackTrace();
				}
				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	public void showStats(TCPStatistics tcpStatistics) {
		try {
			flowStats.getChildren().clear();
			StringBuilder sb = new StringBuilder();
			sb.append("Total Execution Time (ms) = " + tcpStatistics.executionTime + "\r\n");
			sb.append("Total Sent Packets Count = " + tcpStatistics.totalPacketsSent + "\r\n");
			sb.append("Total Lost Packets Count = " + tcpStatistics.lostTotalCount + "\r\n");
			sb.append(String.format("Loss Rate = %.6f %% \r\n" , (tcpStatistics.lostTotalCount/(double)tcpStatistics.totalPacketsSent*100) ));
			sb.append("Lost Payload Packets Count = " + tcpStatistics.lostPacketsCount + "\r\n");
			sb.append("Lost Acks Count = " + tcpStatistics.lostAcksCount+ "\r\n");
			sb.append("Total Re-transmission Count = " + tcpStatistics.retransmissionsCount + "\r\n");
			sb.append("Timeout Count = " + tcpStatistics.timeoutCount+ "\r\n");
			sb.append("Effective Timeout Count = " + tcpStatistics.timeoutCount_eff+ "\r\n");			
			sb.append("Triple Duplicate Ack Count = " + tcpStatistics.tripleDupAckCount+ "\r\n");
			sb.append("Average RTT (ms) = " + tcpStatistics.averageRTT+ "\r\n");
			Text txt1 = new Text(sb.toString());
			txt1.setId("stats");
			flowStats.getChildren().add(txt1);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void showChart()
	{
		Stage dialogStage = new Stage();
	    dialogStage.setTitle("Congestion Window Statistics");
	    dialogStage.initModality(Modality.NONE);
	    dialogStage.initOwner(primaryStage);
		BorderPane p = new BorderPane();
		
		NumberAxis xAxis = new NumberAxis();
		xAxis.setLabel("Time ( in RTTs )");
		// Customize the X-Axis, so points are scattered uniformly
		xAxis.setAutoRanging(false);
		xAxis.setLowerBound(0);
		 
		// Create the Y-Axis
		NumberAxis yAxis = new NumberAxis();
		yAxis.setLabel("Congestion Window Size ( in MSS )");
		// Create the LineChart
		LineChart<Number,Number> chart = new LineChart<>(xAxis, yAxis);
		// Set the Title for the Chart
		chart.setTitle("Congestion Window Growth Chart");
		// Set the Data for the Chart
		XYChart.Series<Number, Number> series1 = new XYChart.Series<Number, Number>();
		XYChart.Series<Number, Number> series2 = new XYChart.Series<Number, Number>();
		long rttNumMax1 = 0, rttNumMax2 = 0;
		rttNumMax1 = readChartData(TCPCoordinator.cwndLogFilename_client, series1 );
		rttNumMax2 = readChartData(TCPCoordinator.cwndLogFilename_server, series2 );
		long rttNum = Math.max(rttNumMax1, rttNumMax2);
		series1.setName("Client");
		series2.setName("Server");
//		BufferedReader br = null;
//		try {
//			br = new BufferedReader(new FileReader(new File(TCPCoordinator.cwndLogFilename_client)));
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		long count = 0;
//		long batchCount = 1000;
//		ArrayList<XYChart.Data<Number, Number>> data = new ArrayList<XYChart.Data<Number, Number>>(); 
//		while(true){
//			try {
//				String str = br.readLine();
//				if(str == null || str.isEmpty()){
//					if(data.size() > 0)
//						series1.getData().addAll(data);
//					break;
//				}
//				rttNum = Long.parseLong(str);
//				str = br.readLine();
//				if(str == null || str.isEmpty()){
//					if(data.size() > 0)
//						series1.getData().addAll(data);
//					break;
//				}
//				long cwndSize = Long.parseLong(str);
//				data.add(new XYChart.Data<Number, Number>(rttNum, cwndSize));
////				rttNum++;
//				count++;
//				if(count >= batchCount){
//					series1.getData().addAll(data);
//					data= new ArrayList<XYChart.Data<Number, Number>>();
//					count = 0;
//				}
//			} catch (EOFException ex) {
//				// TODO Auto-generated catch block
//				break;
//			}catch (IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		}
		
		xAxis.setUpperBound(rttNum);
		long n = rttNum/20;
		xAxis.setTickUnit(n);
		
//		series1.getData().add(new XYChart.Data<Number, Number>(1950, 358));
//		series1.getData().add(new XYChart.Data<Number, Number>(2000, 1017));
//		series1.getData().add(new XYChart.Data<Number, Number>(2050, 1531));
//		series1.getData().add(new XYChart.Data<Number, Number>(2100, 1458));
//		series1.getData().add(new XYChart.Data<Number, Number>(2150, 1308));

		ObservableList<XYChart.Series<Number, Number>> chartData = FXCollections.<XYChart.Series<Number, Number>>observableArrayList();
		chartData.add(series1);
		chartData.add(series2);
		chart.setData(chartData);
//		chart.setLegendVisible(false);
//		chart.setCreateSymbols(false);
		
		
		
		p.setCenter(chart);


	    Scene scene = new Scene(p);
		try{
			scene.getStylesheets().add(getClass().getResource("../styles.css").toExternalForm());
		}
		catch(Exception e){
			// used to handle loading css from jar
			Path currentRelativePath = Paths.get("");
			String s = "file:///" + currentRelativePath.toAbsolutePath().toString() + "/styles.css";
			s = s.replace("\\", "/");
			s = s.replace(" ", "%20");
			System.out.println(s);
			scene.getStylesheets().add(s);
		}
	    dialogStage.setScene(scene);
	    dialogStage.show();
	}

	public void showChartInflight()
	{
		Stage dialogStage = new Stage();
	    dialogStage.setTitle("In Flight Packets Statistics");
	    dialogStage.initModality(Modality.NONE);
	    dialogStage.initOwner(primaryStage);
		BorderPane p = new BorderPane();
		
		NumberAxis xAxis = new NumberAxis();
		xAxis.setLabel("Time ( in RTTs )");
		// Customize the X-Axis, so points are scattered uniformly
		xAxis.setAutoRanging(false);
		xAxis.setLowerBound(0);
		 
		// Create the Y-Axis
		NumberAxis yAxis = new NumberAxis();
		yAxis.setLabel("In Flight Size ( in MSS )");
		// Create the LineChart
		LineChart<Number,Number> chart = new LineChart<>(xAxis, yAxis);
		// Set the Title for the Chart
		chart.setTitle("Actual Congestion Window Growth Chart");
		// Set the Data for the Chart
		XYChart.Series<Number, Number> series1 = new XYChart.Series<Number, Number>();
		XYChart.Series<Number, Number> series2 = new XYChart.Series<Number, Number>();
		ObservableList<XYChart.Series<Number, Number>> chartData = FXCollections.<XYChart.Series<Number, Number>>observableArrayList();
		long rttNumMax1 = 0, rttNumMax2 = 0;
		if(TCPCoordinator.inflightLogWriter_client != null){
			rttNumMax1 = readChartData(TCPCoordinator.inflightLogFilename_client, series1 );
			series1.setName("Client");
			chartData.add(series1);
		}
		if(TCPCoordinator.inflightLogWriter_server != null){
			rttNumMax2 = readChartData(TCPCoordinator.inflightLogFilename_server, series2 );
			series2.setName("Server");
			chartData.add(series2);
		}
		
		long rttNum = Math.max(rttNumMax1, rttNumMax2);
		xAxis.setUpperBound(rttNum);
		long n = rttNum/20;
		xAxis.setTickUnit(n);

		chart.setData(chartData);
//		chart.setLegendVisible(false);
//		chart.setCreateSymbols(false);
		
		
		
		p.setCenter(chart);


	    Scene scene = new Scene(p);
		try{
			scene.getStylesheets().add(getClass().getResource("../styles.css").toExternalForm());
		}
		catch(Exception e){
			// used to handle loading css from jar
			Path currentRelativePath = Paths.get("");
			String s = "file:///" + currentRelativePath.toAbsolutePath().toString() + "/styles.css";
			s = s.replace("\\", "/");
			s = s.replace(" ", "%20");
			System.out.println(s);
			scene.getStylesheets().add(s);
		}
	    dialogStage.setScene(scene);
	    dialogStage.show();
	}

	public void showChartInflightTime()
	{
		Stage dialogStage = new Stage();
	    dialogStage.setTitle("In Flight Packets Statistics w/Time");
	    dialogStage.initModality(Modality.NONE);
	    dialogStage.initOwner(primaryStage);
		BorderPane p = new BorderPane();
		
		NumberAxis xAxis = new NumberAxis();
		xAxis.setLabel("Time (ms)");
		// Customize the X-Axis, so points are scattered uniformly
		xAxis.setAutoRanging(false);
		xAxis.setLowerBound(0);
		 
		// Create the Y-Axis
		NumberAxis yAxis = new NumberAxis();
		yAxis.setLabel("In Flight Size ( in MSS )");
		// Create the LineChart
		LineChart<Number,Number> chart = new LineChart<>(xAxis, yAxis);
		// Set the Title for the Chart
		chart.setTitle("Actual Congestion Window Growth Chart");
		// Set the Data for the Chart
		XYChart.Series<Number, Number> series1 = new XYChart.Series<Number, Number>();
		XYChart.Series<Number, Number> series2 = new XYChart.Series<Number, Number>();
		ObservableList<XYChart.Series<Number, Number>> chartData = FXCollections.<XYChart.Series<Number, Number>>observableArrayList();
		long rttNumMax1 = 0, rttNumMax2 = 0;
		if(TCPCoordinator.inflightTimeLogWriter_client != null){
			rttNumMax1 = readChartData(TCPCoordinator.inflightTimeLogFilename_client, series1 );
			series1.setName("Client");
			chartData.add(series1);
		}
		if(TCPCoordinator.inflightTimeLogWriter_server != null){
			rttNumMax2 = readChartData(TCPCoordinator.inflightTimeLogFilename_server, series2 );
			series2.setName("Server");
			chartData.add(series2);
		}
		
		long rttNum = Math.max(rttNumMax1, rttNumMax2);
		xAxis.setUpperBound(rttNum);
		long n = (long)(rttNum/20);
		xAxis.setTickUnit(n);

		chart.setData(chartData);
//		chart.setLegendVisible(false);
//		chart.setCreateSymbols(false);
		
		
		
		p.setCenter(chart);


	    Scene scene = new Scene(p);
		try{
			scene.getStylesheets().add(getClass().getResource("../styles.css").toExternalForm());
		}
		catch(Exception e){
			// used to handle loading css from jar
			Path currentRelativePath = Paths.get("");
			String s = "file:///" + currentRelativePath.toAbsolutePath().toString() + "/styles.css";
			s = s.replace("\\", "/");
			s = s.replace(" ", "%20");
			System.out.println(s);
			scene.getStylesheets().add(s);
		}
	    dialogStage.setScene(scene);
	    dialogStage.show();
	}
	public long  readChartData(String filename, XYChart.Series<Number, Number> series1){
//		XYChart.Series<Number, Number> series1 = new XYChart.Series<Number, Number>();
		
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(filename));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return 0;
		}
		long rttNum = 0;
		long count = 0;
		long batchCount = 1000;
		ArrayList<XYChart.Data<Number, Number>> data = new ArrayList<XYChart.Data<Number, Number>>(); 
		while(true){
			try {
				String str = br.readLine();
				if(str == null || str.isEmpty()){
					if(data.size() > 0)
						series1.getData().addAll(data);
					break;
				}
				rttNum = Long.parseLong(str);
				str = br.readLine();
				if(str == null || str.isEmpty()){
					if(data.size() > 0)
						series1.getData().addAll(data);
					break;
				}
				long cwndSize = Long.parseLong(str);
				data.add(new XYChart.Data<Number, Number>(rttNum, cwndSize));
//				rttNum++;
				count++;
				if(count >= batchCount){
					series1.getData().addAll(data);
					data= new ArrayList<XYChart.Data<Number, Number>>();
					count = 0;
				}
			} catch (EOFException ex) {
				// TODO Auto-generated catch block
				break;
			}catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return rttNum ;
	}

	public double  readChartDataTime(String filename, XYChart.Series<Number, Number> series1){
//		XYChart.Series<Number, Number> series1 = new XYChart.Series<Number, Number>();
		
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(filename));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return 0;
		}
		double time = 0;
		long count = 0;
		long batchCount = 1000;
		ArrayList<XYChart.Data<Number, Number>> data = new ArrayList<XYChart.Data<Number, Number>>(); 
		while(true){
			try {
				String str = br.readLine();
				if(str == null || str.isEmpty()){
					if(data.size() > 0)
						series1.getData().addAll(data);
					break;
				}
				time = Double.parseDouble(str);
				str = br.readLine();
				if(str == null || str.isEmpty()){
					if(data.size() > 0)
						series1.getData().addAll(data);
					break;
				}
				long cwndSize = Long.parseLong(str);
				data.add(new XYChart.Data<Number, Number>(time, cwndSize));
//				rttNum++;
				count++;
				if(count >= batchCount){
					series1.getData().addAll(data);
					data= new ArrayList<XYChart.Data<Number, Number>>();
					count = 0;
				}
			} catch (EOFException ex) {
				// TODO Auto-generated catch block
				break;
			}catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return time ;
	}
}
