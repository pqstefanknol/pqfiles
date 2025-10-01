**Prepare a reusable VM (no cluster config yet):**

```
PHASE=base ASSUME_YES=true HOSTNAME=brn-base TZ=Europe/Amsterdam sudo -E ./k3s-node-setup.sh
TEMPLATE_PREP=true ASSUME_YES=true sudo -E ./k3s-node-setup.sh
# Power off → convert to template → clone per customer
```


**At the customer (first server):**
```
PHASE=k3s ROLE=server CLUSTER_INIT=true API_VIP=10.0.0.10 ASSUME_YES=true sudo -E ./k3s-node-setup.sh
```

**Join server or agent:**
```
PHASE=k3s ROLE=server CLUSTER_INIT=false SERVER_URL=https://10.0.0.10:6443 TOKEN=$(cat /var/lib/rancher/k3s/server/node-token) ASSUME_YES=true sudo -E ./k3s-node-setup.sh
# or
PHASE=k3s ROLE=agent SERVER_URL=https://10.0.0.10:6443 TOKEN=... ASSUME_YES=true sudo -E ./k3s-node-setup.sh
```
