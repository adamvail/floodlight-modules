package edu.wisc.cs.project.secure;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecureFlowRemovedListener implements IOFMessageListener, IFloodlightModule{
	
      protected IFloodlightProviderService floodlightProvider;
	  protected static Logger logger;
	  Secure secure;
	  private int removalCount = 0;

	  @Override
	  public String getName() {
	    // TODO Auto-generated method stub
	    return "Secure Flow Removed Listener";
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
	    logger = LoggerFactory.getLogger(SecureFlowRemovedListener.class);
	    secure = Secure.getInstance();
	  }

	  @Override
	  public void startUp(FloodlightModuleContext context) {
	    // TODO Auto-generated method stub
	    floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
	  }

	  @Override
	  public net.floodlightcontroller.core.IListener.Command receive(
	      IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
	    
		// This should be true since I'm' only registered for FLOW_REMOVED packets
		if(msg.getType() == OFType.FLOW_REMOVED){
			//logger.debug("\n\nGOT A FLOW REMOVED PACKET\n");
			secure.removeFlowRule((OFFlowRemoved)msg, sw.getId());
			removalCount++;
		//	logger.debug("Rules Removed: " + this.removalCount);
		}
		return Command.CONTINUE;
	  }
}
