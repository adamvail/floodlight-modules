package edu.wisc.cs.bootcamp.sdn.learningswitch;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

public class LearningSwitch implements IOFMessageListener, IFloodlightModule, IOFSwitchListener {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;
	protected HashMap<Long, Short> lookupTable = new HashMap<Long, Short>(); 
	
    protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 60; // in seconds
    protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "Learning Switch";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(LearningSwitch.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFSwitchListener(this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		//logger.info("Receive a packet!");
		
		// look to see if we should drop the packet
				
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);	
		
		if(eth.getEtherType() != Ethernet.TYPE_IPv4){
			return Command.CONTINUE;
		}
		
		switch(msg.getType()){
			case PACKET_IN:
			
		        OFPacketIn pi = (OFPacketIn) msg;
		    			
		        IPv4 ipPacket = (IPv4) eth.getPayload();
//				byte proto = ipPacket.getProtocol();
				
				//logger.info("Time to do normal learning switch stuff");
				//logger.info("Here is the MAC being processed --> " + eth.getSourceMAC().toString());
				
				if(!lookupTable.containsKey(eth.getSourceMAC().toLong())){
				//	logger.info("Inserting key into table --> " + eth.getSourceMAC().toString());
					lookupTable.put(eth.getSourceMAC().toLong(), ((OFPacketIn) msg).getInPort());	
				}
				
				short outPort = -1;
				if(lookupTable.containsKey(eth.getDestinationMAC().toLong())){
					outPort = lookupTable.get(eth.getDestinationMAC().toLong());
				}
				
				
				ArrayList<OFAction> poAction = new ArrayList<OFAction>();
				//short poActionLength = 0;
		        
		        if(outPort != -1){	        	
		        	if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP && ((TCP)ipPacket.getPayload()).getDestinationPort() == ((short)80)){
		        		createRemapTransportPortRule(pi, outPort, sw, eth.getSourceMACAddress());
		        		
		        		OFActionTransportLayerDestination poRemapPort = new OFActionTransportLayerDestination((short)443);
		        		//poRemapPort.setLength((short)OFActionTransportLayerDestination.MINIMUM_LENGTH);
		        		poAction.add((OFAction)poRemapPort);
		        		
		        	/*	OFActionTransportLayerSource poRemapTpSrc = new OFActionTransportLayerSource((short)443);
		        		poAction.add(poRemapTpSrc);
		        	*/	
		        		OFActionOutput outputPort = new OFActionOutput((short)outPort);
		        		//outputPort.setLength((short)OFActionOutput.MINIMUM_LENGTH);
		        		poAction.add(outputPort);
		        		logger.info("Finishing work for port 80");
		        	}
		        	else{
		        		OFActionOutput action = new OFActionOutput()
	        				.setPort(outPort);
		        		action.setLength((short)OFActionOutput.MINIMUM_LENGTH);
		        		poAction.add(action);
		        		//poActionLength += (short)OFActionOutput.MINIMUM_LENGTH;
		        		
		        		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		        		short actionLength = (short)OFFlowMod.MINIMUM_LENGTH;
		        		
			        	// set up flow rule
			        	OFFlowMod rule = new OFFlowMod();
			        	rule.setType(OFType.FLOW_MOD);
			        	rule.setCommand(OFFlowMod.OFPFC_ADD); 
			        	rule.setPriority((short)1000);
			        	
			        	OFMatch match = new OFMatch();
			        	match.loadFromPacket(pi.getPacketData(), pi.getInPort());
			        	
		        		match.setWildcards(~(OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO));
		        		match.setDataLayerType((short)0x0800);
		       
		        		rule.setMatch(match);
		        		rule.setIdleTimeout(LearningSwitch.FLOWMOD_DEFAULT_IDLE_TIMEOUT);
			        	rule.setHardTimeout(LearningSwitch.FLOWMOD_DEFAULT_HARD_TIMEOUT);
			        	
			        	OFAction outputTo = new OFActionOutput(outPort);
			        	actions.add(outputTo);
			        	actionLength += (short)OFActionOutput.MINIMUM_LENGTH;
			        	
			        	rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
			        	rule.setActions(actions);		        			        	
			        	
			        	rule.setLength((short) actionLength);
			        	
			        	try{
			        		sw.write(rule, null);
			        		sw.flush();
			        	}catch(Exception e){
			        		e.printStackTrace();
			        	}
			        	
		        	}
		        	// Always add the output port, need this for actually sending the data		        	
		        }
		        else{
		        	logger.info("--------FLOOD THE PACKET-------");
		        	OFActionOutput action = new OFActionOutput()
		        		.setPort((short) OFPort.OFPP_FLOOD.getValue());
		        	//action.setLength((short)OFActionOutput.MINIMUM_LENGTH);
		        	poAction.add((OFAction)action);
		        	//poActionLength += (short)OFActionOutput.MINIMUM_LENGTH;
		        	
		        	// need to remap the ports even on a flood
		        	if(ipPacket.getProtocol() == IPv4.PROTOCOL_TCP && ((TCP)ipPacket.getPayload()).getDestinationPort() == ((short)80)){
		        		logger.info("Flooding a port 80 packet!");
		        		OFActionTransportLayerDestination poRemapPort = new OFActionTransportLayerDestination((short)443);
		        		//poRemapPort.setLength((short)OFActionTransportLayerDestination.MINIMUM_LENGTH);
		        		poAction.add(((OFAction)poRemapPort));
		        		
		        		/*OFActionTransportLayerSource remapTpSrc = new OFActionTransportLayerSource((short)443);
		        		poAction.add(remapTpSrc);
		        		*/
		        		
		        		//poActionLength += (short)OFActionTransportLayerDestination.MINIMUM_LENGTH;
		        	} 	        	
		        }
		        		        
		        sendPacket(pi, poAction, cntx, sw);
		              
			default:
				break;
		}

        return Command.CONTINUE;
	}
	
	private void sendPacket(OFPacketIn pi, ArrayList<OFAction> actions, FloodlightContext cntx, IOFSwitch sw){
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
        po.setBufferId(pi.getBufferId());
        po.setInPort(pi.getInPort());
		
        short actionsLength = 0;
        po.setActions(actions);
  
        if(actions.size() == 1){
        	po.setActionsLength((short)OFActionOutput.MINIMUM_LENGTH);
        }
        else if(actions.size() == 2){
        	po.setActionsLength(((short)(OFActionOutput.MINIMUM_LENGTH + OFActionTransportLayerDestination.MINIMUM_LENGTH)));
        	//logger.info("Sending packet from port 80 destined for 443!");
        }
        else if(actions.size() == 3){
        	po.setActionsLength(((short)(OFActionOutput.MINIMUM_LENGTH + OFActionTransportLayerDestination.MINIMUM_LENGTH + OFActionTransportLayerSource.MINIMUM_LENGTH)));	
        }
        else{
        	logger.info("MORE THAN 2 ACTIONS IN ARRAY....WTF?");
        	for(OFAction act : actions){
        		act.toString();
        	}      	
        }
        //po.setActionsLength((short)actionsLength);
        
        if (pi.getBufferId() == 0xffffffff) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }
        
        try {
            sw.write(po, cntx);
            sw.flush();
        } catch (IOException e) {
            logger.error("Failure writing PacketOut", e);
        }
        
        actions.clear();
        //logger.info("DONE WRITING");
	}
	
	private void createRemapTransportPortRule(OFPacketIn pi, short outPort, IOFSwitch sw, byte[] src){
		//logger.info("Trying to NAT----------------");
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		short actionLength = ((short)OFFlowMod.MINIMUM_LENGTH);
		
		OFFlowMod rule = (OFFlowMod)(OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
    	rule.setType(OFType.FLOW_MOD);
    	rule.setCommand(OFFlowMod.OFPFC_ADD);
    	rule.setPriority((short)3000);
    		
    	OFMatch match = new OFMatch();
    	match.loadFromPacket(pi.getPacketData(), pi.getInPort());
    	
		match.setWildcards(~(OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_DST));
		match.setDataLayerType((short)0x0800);
		//match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		match.setTransportDestination((short)80);	        		
		rule.setMatch(match);
		
		rule.setHardTimeout((short)0);
		rule.setIdleTimeout((short)30);
		
		OFActionTransportLayerDestination remapPort80 = new OFActionTransportLayerDestination((short)443);
		actions.add(remapPort80);
		actionLength += ((short)OFActionTransportLayerDestination.MINIMUM_LENGTH);
	/*	
		OFActionTransportLayerSource remapTpSrc = new OFActionTransportLayerSource((short)443);
		actions.add(remapTpSrc);
	*/	
		OFActionOutput outputPort = new OFActionOutput((short)outPort);
		actions.add(outputPort);
		actionLength += ((short)OFActionOutput.MINIMUM_LENGTH);
		
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setActions(actions);
		rule.setLength(((short)(OFFlowMod.MINIMUM_LENGTH + OFActionTransportLayerDestination.MINIMUM_LENGTH + /*OFActionTransportLayerSource.MINIMUM_LENGTH +*/ OFActionOutput.MINIMUM_LENGTH)));
		
		try {
			sw.write(rule, null);
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//return;
	
		OFFlowMod reverseRule = (OFFlowMod)(OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		reverseRule.setType(OFType.FLOW_MOD);
    	reverseRule.setCommand(OFFlowMod.OFPFC_ADD);
    	reverseRule.setPriority((short)3000);
    	
		actions.clear();
		actionLength = (short)OFFlowMod.MINIMUM_LENGTH;
		
		OFMatch reverseMatch = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		
		reverseMatch.setWildcards(~(OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_NW_PROTO));
		
		reverseMatch.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		reverseMatch.setDataLayerType((short)0x0800);
		reverseMatch.setTransportSource((short)443);
		reverseMatch.setDataLayerDestination(src);
		
		reverseRule.setMatch(reverseMatch);
		reverseRule.setHardTimeout((short)0);
		reverseRule.setIdleTimeout((short)30);
		
	/*	OFAction remapPort443 = new OFActionTransportLayerDestination((short)match.getTransportSource());
		actions.add(remapPort443);
		actionLength += (short)OFActionTransportLayerDestination.MINIMUM_LENGTH;
	*/	
		OFAction remapPortSource = new OFActionTransportLayerSource((short)80);
		actions.add(remapPortSource);
		
		OFActionOutput reverseOutPort = new OFActionOutput((short)pi.getInPort());
		actions.add(reverseOutPort);
		actionLength += (short)OFActionOutput.MINIMUM_LENGTH;
		
		//reverseRule.setLength((short)actionLength);
		
		reverseRule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		reverseRule.setActions(actions);
		//reverseRule.setLength(((short)(OFFlowMod.MINIMUM_LENGTH + OFActionTransportLayerDestination.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)));
		//reverseRule.setLength(((short)(OFFlowMod.MINIMUM_LENGTH + OFActionTransportLayerSource.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH)));
		reverseRule.setLength(((short)(OFFlowMod.MINIMUM_LENGTH + OFActionTransportLayerSource.MINIMUM_LENGTH +OFActionOutput.MINIMUM_LENGTH)));
		
		//logger.info("WRITING REVERSE RULE TO SWITCH");
		
		try {
			sw.write(reverseRule, null);
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//logger.info("Exiting remap rules");
		 
	}
	
	private void packetOutRemapTransportPort(OFPacketIn pi, OFPacketOut po, short remapPort){
    	OFActionTransportLayerDestination action = new OFActionTransportLayerDestination();
    	action.setTransportPort(remapPort);
        po.setActions(Collections.singletonList((OFAction)action));
        po.setActionsLength((short) OFActionTransportLayerDestination.MINIMUM_LENGTH);

        // set data if is is included in the packetin
        if (pi.getBufferId() == 0xffffffff) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }
	}

	@Override
	public void addedSwitch(IOFSwitch sw) {
		// TODO Auto-generated method stub
		// Put in static drop rules
		//logger.info("Switch was added!! ------> Installing static rules");
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		dropUDP(sw);				
		dropTelnet(sw);
		installStaticPunt80ToController(sw);
		//installStaticPunt443ToController(sw);
	}

	@Override
	public void removedSwitch(IOFSwitch sw) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(Long switchId) {
		// TODO Auto-generated method stub
		
	}
	
	public void dropTelnet(IOFSwitch sw){
		//logger.info("Installing static rule to drop telnet");
		OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
    	rule.setType(OFType.FLOW_MOD);
    	rule.setCommand(OFFlowMod.OFPFC_ADD);
    	
    	OFMatch match = new OFMatch();

    	match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_TP_DST));	
    	match.setDataLayerType((short)0x0800);
    	match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
    	match.setTransportDestination((short)23);
    	 
    	rule.setMatch(match);
    	rule.setIdleTimeout((short)0);
    	rule.setHardTimeout((short)0);
    	
    	rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
    	
    	rule.setPriority((short)2000);
    	
    	rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH));
    	
    	try{
    		sw.write(rule, null);
    		sw.flush();
    	}catch(Exception e){
    		e.printStackTrace();
    	}
	}
	
	public void dropUDP(IOFSwitch sw){
		//logger.warn("Static Rule to drop UDP");
    	// set up flow rule
    	OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
    	rule.setType(OFType.FLOW_MOD);
    	rule.setCommand(OFFlowMod.OFPFC_ADD);
    		
    	OFMatch match = new OFMatch();

    	match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE));
    	match.setDataLayerType((short)0x0800);
    	match.setNetworkProtocol(IPv4.PROTOCOL_UDP);
    	
    	rule.setMatch(match);
    	rule.setIdleTimeout((short)0);
    	rule.setHardTimeout((short)0);
    	
    	rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
    	
    	rule.setPriority((short)2000);
    	
    	rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH));
    	
    	// don't specify action since we want to drop it.
    	
    	try{
    		sw.write(rule, null);
    		sw.flush();
    	}catch(Exception e){
    		e.printStackTrace();
    	}
	}	
	
	public void installStaticPunt80ToController(IOFSwitch sw){
		OFFlowMod rule = (OFFlowMod)(OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
    	rule.setType(OFType.FLOW_MOD);
    	rule.setCommand(OFFlowMod.OFPFC_ADD);
    		
    	OFMatch match = new OFMatch();

    	match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_TP_DST));
    	match.setDataLayerType((short)0x0800);
    	match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
    	match.setTransportDestination((short)80);
    	
    	rule.setMatch(match);
    	rule.setIdleTimeout((short)0);
    	rule.setHardTimeout((short)0);
    	
    	rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
    	
    	rule.setPriority((short)2000);
    	
    	// TODO How to punt to controller action?
    	ArrayList<OFAction> actions = new ArrayList<OFAction>();
    	OFAction outputTo = new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()); 
    	actions.add(outputTo);
    	rule.setActions(actions);
    	
    	rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
    	    	
    	try{
    		sw.write(rule, null);
    		sw.flush();
    	}catch(Exception e){
    		e.printStackTrace();
    	}
	}
	
	public void installStaticPunt443ToController(IOFSwitch sw){
		OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
    	rule.setType(OFType.FLOW_MOD);
    	rule.setCommand(OFFlowMod.OFPFC_ADD);
    		
    	OFMatch match = new OFMatch();

    	match.setWildcards(~(OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_TP_DST));
    	match.setDataLayerType((short)0x0800);
    	match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
    	match.setTransportDestination((short)443);
    	
    	rule.setMatch(match);
    	rule.setIdleTimeout((short)0);
    	rule.setHardTimeout((short)0);
    	
    	rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
    	
    	rule.setPriority((short)2000);
    	
    	// TODO How to punt to controller action?
    	ArrayList<OFAction> actions = new ArrayList<OFAction>();
    	OFAction outputTo = new OFActionOutput((short)OFPort.OFPP_CONTROLLER.getValue()); 
    	actions.add(outputTo);
    	rule.setActions(actions);
    	
    	rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
    	    	
    	try{
    		sw.write(rule, null);
    		sw.flush();
    	}catch(Exception e){
    		e.printStackTrace();
    	}
	}
	
}
