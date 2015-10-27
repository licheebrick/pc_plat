NSLab Packet Classification Platform
-------------------------------------

This framework includes algorithms of both packet classification and classifier 
grouping. Most NSLab algorithms could be evaluated under this framework in 
unified manner. Currently, only HyperSplit [1] and RFG [2] are integrated.

src/common/:
    utilities for rules/trace and range/prefix, sort, buffer, fixed-size mempool
src/clsfy/:
    packet classification algorithms
src/group/:
    classifier grouping algorithms

rule_trace/rules/origin:
    original evaluated classifiers at http://www.arl.wustl.edu/~hs1/
rule_trace/rules/rfg:
    group results of upper classifiers using RFG
rule_trace/traces/origin:
    original evaluated traces at http://www.arl.wustl.edu/~hs1/

To build the framework, just run 'make' in this directory. And the built result 
is bin/pc_plat. It runs either in packet classification (pc) mode or in 
classifier grouping (grp) mode. Run ./bin/pc_plat without arguments or with -h, 
--help to see its help.


Run in grp mode:
-----------------
Here is the example, to get the group result of fw1_10K classifier using RFG.
The group result is written to the group_result.txt file.

./bin/pc_plat -g rfg -f wustl -r rule_trace/rules/origin/fw1_10K


Run in pc mode:
----------------
Here is the example, to get the performance of HyperSplit algorithm on RFG 
group result. The program will load rules and trace into the memory, build 
HyperSplit classification tree and go through the trace.
The build and search time will be displayed in microsecond (us).
The classification speed will be displayed in packet per second (pps).
Please make sure the rule and trace are in correspondence with each other.

./bin/pc_plat -p hs -f wustl_g -r rule_trace/rules/rfg/fw1_10K 
-t rule_trace/traces/origin/fw1_10K_trace

To get the performance of HyperSplit algorithm on original classifier, you 
should comment out line 416 and 437 in src/clsfy/hypersplit.c and remove 
comments on line 415 and 436 in the same file (feel so sorry for this hard 
code -_-). After rebuilding the framework, run following command:

./bin/pc_plat -p hs -f wustl -r rule_trace/rules/origin/acl1_10K 
-t rule_trace/traces/origin/acl1_10K_trace


Rule and trace format:
-----------------------
The original rule format is "@src_ip dst_ip src_port dst_port proto".
Both src_ip and dst_ip are ranges in "dot-decimal notation/mask" format.
Both src_port and dst_port are ranges in "begin : end" format.
proto is in "value/mask" format, where the mask value is either 0x00 or 0xff.
0x00 means proto is wildcard, and 0xff means proto is specified by value.

Each classifier group is led by "#group_id,group_rule_num", and followed with 
its rules. The rule format is "@src_ip,dst_ip,src_port,dst_port,proto,orig_id".
Top five fields are in "begin,end" format. And the last field is an integer.

The trace format is "src_ip dst_ip src_port dst_port proto matched_rule".


Reference
----------
[1] Y. Qi, L. Xu, B. Yang, Y. Xue, and J. Li. Packet Classification Algorithms: 
    From Theory to Practice. In Proc. of IEEE INFOCOM, 2009.
[2] X. Wang, C. Chen, and J. Li. Replication Free Rule Grouping for Packet 
    Classification. In Proc. of ACM SIGCOMM, 2013.


If any question, please contact: Xiang Wang (xiang.wang.s@gmail.com)

