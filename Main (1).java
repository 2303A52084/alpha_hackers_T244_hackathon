import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

public class Main {

    public static void main(String[] args) {
        FirewallSystem firewall = new FirewallSystem();
        
        // Sample policies
        firewall.updateRules(Arrays.asList(
            new FirewallRule("chrome.exe", "ALLOW_GOOGLE", ".*google\\.com", 443, "TCP", true),
            new FirewallRule("zoom.exe", "ALLOW_ZOOM", ".*zoom\\.us", 443, "TCP", true),
            new FirewallRule("*", "BLOCK_MALICIOUS", ".*malicious\\.com", -1, "ANY", false)
        ));
        
        // Simulate network events
        firewall.processEvent(new NetworkEvent("chrome.exe", "www.google.com", 443, "TCP", 5000));
        firewall.processEvent(new NetworkEvent("zoom.exe", "meeting.zoom.us", 443, "TCP", 3000));
        firewall.processEvent(new NetworkEvent("malware.exe", "download.malicious.com", 80, "TCP", 10000000));
        
        firewall.shutdown();
    }
}

class FirewallSystem {
    private List<FirewallRule> rules = new ArrayList<>();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    
    public void processEvent(NetworkEvent event) {
        executor.execute(() -> {
            FirewallRule matchingRule = findMatchingRule(event);
            
            if (matchingRule != null) {
                if (matchingRule.isAllowed()) {
                    System.out.printf("[ALLOWED] %s → %s:%d (%s) by rule %s%n",
                        event.getAppName(), event.getDestination(), 
                        event.getPort(), event.getProtocol(), matchingRule.getRuleId());
                    
                    // Check for anomalies
                    if (event.getBytesSent() > 5000000) { // 5MB threshold
                        System.out.printf("[ALERT] Large data transfer: %s sending %d bytes to %s%n",
                            event.getAppName(), event.getBytesSent(), event.getDestination());
                    }
                } else {
                    System.out.printf("[BLOCKED] %s → %s:%d (%s) by rule %s%n",
                        event.getAppName(), event.getDestination(), 
                        event.getPort(), event.getProtocol(), matchingRule.getRuleId());
                }
            } else {
                System.out.printf("[BLOCKED] %s → %s:%d (%s) - No matching rule%n",
                    event.getAppName(), event.getDestination(), 
                    event.getPort(), event.getProtocol());
            }
        });
    }
    
    private FirewallRule findMatchingRule(NetworkEvent event) {
        for (FirewallRule rule : rules) {
            if (rule.matches(event)) {
                return rule;
            }
        }
        return null;
    }
    
    public void updateRules(List<FirewallRule> newRules) {
        this.rules = new ArrayList<>(newRules);
    }
    
    public void shutdown() {
        executor.shutdown();
    }
}

class NetworkEvent {
    private final String appName;
    private final String destination;
    private final int port;
    private final String protocol;
    private final long bytesSent;
    
    public NetworkEvent(String appName, String destination, int port, String protocol, long bytesSent) {
        this.appName = appName;
        this.destination = destination;
        this.port = port;
        this.protocol = protocol;
        this.bytesSent = bytesSent;
    }
    
    public String getAppName() { return appName; }
    public String getDestination() { return destination; }
    public int getPort() { return port; }
    public String getProtocol() { return protocol; }
    public long getBytesSent() { return bytesSent; }
}

class FirewallRule {
    private final String appName;
    private final String ruleId;
    private final Pattern destinationPattern;
    private final int port;
    private final String protocol;
    private final boolean allow;
    
    public FirewallRule(String appName, String ruleId, String destinationPattern, 
                      int port, String protocol, boolean allow) {
        this.appName = appName;
        this.ruleId = ruleId;
        this.destinationPattern = Pattern.compile(destinationPattern);
        this.port = port;
        this.protocol = protocol;
        this.allow = allow;
    }
    
    public boolean matches(NetworkEvent event) {
        boolean appMatches = appName.equals("*") || appName.equalsIgnoreCase(event.getAppName());
        boolean destMatches = destinationPattern.matcher(event.getDestination()).matches();
        boolean portMatches = port == -1 || port == event.getPort();
        boolean protoMatches = protocol.equalsIgnoreCase("ANY") || 
                              protocol.equalsIgnoreCase(event.getProtocol());
        
        return appMatches && destMatches && portMatches && protoMatches;
    }
    
    public String getRuleId() { return ruleId; }
    public boolean isAllowed() { return allow; }
}