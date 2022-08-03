from django.conf.urls import url
from clouds_tools.views import SingleScanPortView, SingleScanObsView, \
    SingleScanPortProgressView, SingleScanObsProgressView, PortsListView

urlpatterns = [
    url(r'^single_scan_port/progress$', SingleScanPortProgressView.as_view()),
    url(r'^single_scan_port$', SingleScanPortView.as_view()),
    url(r'^single_scan_obs/progress$', SingleScanObsProgressView.as_view()),
    url(r'^single_scan_obs$', SingleScanObsView.as_view()),
    url(r'^port_list$', PortsListView.as_view()),
]
