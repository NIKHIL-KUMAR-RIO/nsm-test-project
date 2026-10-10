package com.nsm.backend;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class NsmBackendApplication {

    private static final Logger log = LoggerFactory.getLogger(NsmBackendApplication.class);

    public static void main(String[] args) {
        ConfigurableApplicationContext ctx = SpringApplication.run(NsmBackendApplication.class, args);
        String port = ctx.getEnvironment().getProperty("server.port", "8080");

        log.info("""
                
                ========================================================================================
                   _   _ ____  __  __   ____  _       _    __                            
                  | \\ | / ___||  \\/  | |  _ \\| | __ _| |_ / _| ___  _ __ _ __ ___   
                  |  \\| \\___ \\| |\\/| | | |_) | |/ _` | __| |_ / _ \\| '__| '_ ` _ \\  
                  | |\\  |___) | |  | | |  __/| | (_| | |_|  _| (_) | |  | | | | | | 
                  |_| \\_|____/|_|  |_| |_|   |_|\\__,_|\\__|_|  \\___/|_|  |_| |_| |_| 
                  
                  ACADEMIC 5-MODULE NETWORK SECURITY MONITORING (NSM) PLATFORM
                  Java Version: {} | SQLite DB: nsm.db
                  
                  🌐 Web Dashboard: http://localhost:{}/
                  📡 API Alerts   : http://localhost:{}/api/alerts
                  📊 API Stats    : http://localhost:{}/api/traffic-stats
                  🛡️ Decoy Probes : Active on ports 2222, 8088, 8888, 9090
                ========================================================================================
                """, Runtime.version(), port, port, port);
    }
}
