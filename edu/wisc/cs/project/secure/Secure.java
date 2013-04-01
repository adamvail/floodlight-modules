package edu.wisc.cs.project.secure;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import net.floodlightcontroller.core.IOFSwitch;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Secure {
	
	protected static Logger logger = LoggerFactory.getLogger(Secure.class);
	
	private HashMap<Long, HashSet<Alias>> aliasSet = new HashMap<Long, HashSet<Alias>>();
	
	/**
	 * This function is used in OFSwitchBase to check rules in the
	 * write functions to make sure the switch should get the rule
	 * @param rule - the rule to be written to the switch
	 * @param sw - the switch that is trying to write the rule, this way
	 * 				a view of the switch's current rules can be constructed
	 * @return - true or false, if the rule is allowed to be written or not
	 */
	
	public static boolean checkFlowRule(OFFlowMod rule, IOFSwitch sw){
		
		logger.debug("------------Secure just received a rule!---------------");
		List<OFAction> actions = rule.getActions();
		
		for(OFAction action : actions){
			logger.debug("Switch " + sw.getId() + ": " + action.toString());
			
		}
		
		return true;
	}

}
