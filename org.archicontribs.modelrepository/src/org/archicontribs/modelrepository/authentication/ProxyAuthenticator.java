/**
 * This program and the accompanying materials
 * are made available under the terms of the License
 * which accompanies this distribution in the file LICENSE.txt
 */
package org.archicontribs.modelrepository.authentication;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

import org.archicontribs.modelrepository.ModelRepositoryPlugin;
import org.eclipse.core.net.proxy.IProxyData;
import org.eclipse.core.runtime.IStatus;

import com.archimatetool.editor.utils.NetUtils;

/**
 * Proxy Authenticator
 * 
 * @author Phillip Beauvoir
 */
public class ProxyAuthenticator {
    
    // Store the default ProxySelector before we set ours
    private static final ProxySelector DEFAULT_PROXY_SELECTOR = ProxySelector.getDefault();
    
    // Our Authenticator
    private static Authenticator AUTHENTICATOR = new Authenticator() {
        @Override
        public PasswordAuthentication getPasswordAuthentication() {
            // If this is a Proxy request, return its credentials
            // Otherwise the requested URL is the endpoint (and not the proxy host)
            // In this case the authentication should not be proxy so return null (and JGit CredentialsProvider will be used)
            if(getRequestorType() == RequestorType.PROXY) {
                URL url = getRequestingURL();
                IProxyData proxyData = NetUtils.getProxyData(url);
                return proxyData == null ? null : new PasswordAuthentication(proxyData.getUserId(), proxyData.getPassword().toCharArray());
            }
            
            // Not a proxy request
            return null;
        }
    };
    
    // Initialise
    public static void init() {
        // This needs to be set in order to avoid this exception when using a Proxy:
        // "Unable to tunnel through proxy. Proxy returns "HTTP/1.1 407 Proxy Authentication Required""
        // It needs to be set before any JGit operations, because it can't be set again
        System.setProperty("jdk.http.auth.tunneling.disabledSchemes", ""); //$NON-NLS-1$ //$NON-NLS-2$
        
        // Added this one too. I think it's for HTTP
        System.setProperty("jdk.http.auth.proxying.disabledSchemes", ""); //$NON-NLS-1$ //$NON-NLS-2$
    }
    
    // Update the proxy details
    public static void update() {
        // Don't use a proxy
        if(!NetUtils.getProxyService().isProxiesEnabled()) {
            clear();
            return;
        }
        
        // The default ProxySelector
        ProxySelector.setDefault(new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                IProxyData proxyData = NetUtils.getProxyData(uri);
                
                if(proxyData == null) {
                    return Arrays.asList(Proxy.NO_PROXY);
                }
                
                // Authentication is used
                if(proxyData.isRequiresAuthentication()) {
                    Authenticator.setDefault(AUTHENTICATOR);
                }
                // No authentication used
                else {
                    Authenticator.setDefault(null);
                }
                
                Proxy proxy = NetUtils.getProxy(proxyData);
                return Arrays.asList(proxy);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ex) {
                ModelRepositoryPlugin.INSTANCE.log(IStatus.ERROR, "Connect failed in ProxySelector", ex); //$NON-NLS-1$
                ex.printStackTrace();
            }
        });
    }
    
    /**
     * Clear the Proxy settings
     */
    public static void clear() {
        Authenticator.setDefault(null);
        ProxySelector.setDefault(DEFAULT_PROXY_SELECTOR);
    }
}
