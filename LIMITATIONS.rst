Known Bigswitch Neutron Plugin Limitations
==========================================

 * Router interfaces within a tenant, even if on different routers, can not have overlapping IP subnets.
 * Names of resources (for example, a network name) can not be updated with a different value.
 * Names of resources can not be duplicated in any place in the deployment.
 * Network names must be specified when creating a network.


Known Bigswitch Neutron Plugin Limitations due to bugs
======================================================

 * When creating an external network, the public gateway IP must be specified.
 * Routers can not be updated if it has an external gateway.
 * Routers can not be created with an external gateway network if that network is a private network.
