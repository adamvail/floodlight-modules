package edu.wisc.cs.project.secure;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import net.floodlightcontroller.core.IOFSwitch;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.action.OFAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Secure {
	
	protected static Logger logger = LoggerFactory.getLogger(Secure.class);
	
	private static HashMap<Long, HashSet<Alias>> aliasSet = new HashMap<Long, HashSet<Alias>>();
	
	/**
	 * This function is used in OFSwitchBase to check rules in the
	 * write functions to make sure the switch should get the rule
	 * @param rule - the rule to be written to the switch
	 * @param sw - the switch that is trying to write the rule, this way
	 * 				a view of the switch's current rules can be constructed
	 * @return - true or false, if the rule is allowed to be written or not
	 */
	
	public static boolean checkFlowRule(OFFlowMod rule, IOFSwitch sw){
		// If there are no rules in the flow table, add this one
		if(aliasSet.get(sw.getId()) == null){
			HashSet<Alias> aliases = new HashSet<Alias>();
			aliases.add(new Alias(rule));
			aliasSet.put(sw.getId(), aliases);
			return true;
		}
		
		HashSet<Alias> aliases = aliasSet.get(sw.getId());
		for(Alias alias : aliases){
			// pairwise comparison of current flow table rules
			// with the candidate rule
			
			if(checkActions(rule.getActions(), alias.getActions()) == true){
				// Actions are the same so add the rule alias to the set
				if(aliasSet.get(sw.getId()).add(new Alias(rule)) == true){
					return true;
				}
				else{
					return true;
				}
			}
			
		}
		
		return true;
	}
	
	/**
	 * Check to see if the actions are equal
	 * 
	 * @param rule
	 * @param sw
	 * @return
	 */
	
	private static boolean checkActions(List<OFAction> cActions, List<OFAction> fActions){
		
		// If they aren't the same size they can't be the same action as a whole
		if(cActions.size() != fActions.size()){
			return false;
		}
		
				
		
		return true;
	}
	
}
