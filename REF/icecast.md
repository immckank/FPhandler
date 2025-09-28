PartialLeak : memory allocation at : (CallICFGNode: { "ln": 347, "cl": 15, "fl": "auth_htpasswd.c" })
                 conditional free path:
                  --> ({ "ln": 349, "cl": 9, "fl": "auth_htpasswd.c" }|False)
                  --> ({ "ln": 349, "cl": 9, "fl": "auth_htpasswd.c" }|True)
                  --> ({ "ln": 360, "cl": 8, "fl": "auth_htpasswd.c" }|False)
                  --> ({ "ln": 360, "cl": 8, "fl": "auth_htpasswd.c" }|True)
                  --> ({ "ln": 370, "cl": 5, "fl": "auth_htpasswd.c" }|True)

误报，所有条件/循环语句后405行有相应的free，349、360的if内也有free。应当是saber认为370的while可能会持续执行导致free不执行

---

Double Free : memory allocation at : (CallICFGNode: { "ln": 186, "cl": 23, "fl": "slave.c" })
                 double free path:
                  --> ({ "ln": 194, "cl": 5, "fl": "slave.c" }|True)
                  --> ({ "ln": 201, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 225, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 232, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 238, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 272, "cl": 17, "fl": "slave.c" }|False)
                  --> ({ "ln": 279, "cl": 17, "fl": "slave.c" }|False)

误报，按上述路径在294行会有free，但之后会立即返回，不会执行到循环外304行的free，或许因saber未理解复杂路径导致

---

Double Free : memory allocation at : (CallICFGNode: { "ln": 426, "cl": 17, "fl": "util.c" })
                 double free path:

误报，saber不知为何没有给出路径，util.c函数内没有free，外部调用中都立即free了，不会引起问题

---

Double Free : memory allocation at : (CallICFGNode: { "ln": 276, "cl": 35, "fl": "thread.c" })
                 double free path:
                  --> ({ "ln": 279, "cl": 13, "fl": "thread.c" }|False)
                  --> ({ "ln": 279, "cl": 13, "fl": "thread.c" }|True)
                  --> ({ "ln": 304, "cl": 13, "fl": "thread.c" }|True)

误报，start只会在两处被释放，一处是317行循环结束后的free，另一处是304行pthread_create创建线程成功后，在_start_routine内被子进程free，但二者不可能同时发生。从double free path看，或许是saber分别识别到了两条路径上各自的free，又将他们混为一谈

---

Double Free : memory allocation at : (CallICFGNode: { "ln": 261, "cl": 22, "fl": "slave.c" })
                 double free path:
                  --> ({ "ln": 194, "cl": 5, "fl": "slave.c" }|True)
                  --> ({ "ln": 201, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 225, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 232, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 238, "cl": 13, "fl": "slave.c" }|False)
                  --> ({ "ln": 272, "cl": 17, "fl": "slave.c" }|False)
                  --> ({ "ln": 279, "cl": 17, "fl": "slave.c" }|False)
                  --> (|True)
                  --> (|True)

误报，不知为何路径信息不全，原代码只在291和301各有一次free，但二者逻辑互斥，或许因saber将路径混为一谈

---

PartialFileClose : file open location at : (CallICFGNode: { "ln": 358, "cl": 22, "fl": "auth_htpasswd.c" })
                 conditional file close path:
                  --> ({ "ln": 370, "cl": 5, "fl": "auth_htpasswd.c" }|True)

误报，389行即有对应fclose，可能是saber认为370的while可能会持续执行导致fclose不执行

---

PartialFileClose : file open location at : (CallICFGNode: { "ln": 359, "cl": 16, "fl": "connection.c" })
                 conditional file close path:
                  --> ({ "ln": 368, "cl": 9, "fl": "connection.c" }|True)

误报，378行即有对应fclose，可能也是while导致误判

---

PartialFileClose : file open location at : (CallICFGNode: { "ln": 338, "cl": 18, "fl": "auth_htpasswd.c" })
                 conditional file close path:
                  --> ({ "ln": 349, "cl": 9, "fl": "auth_htpasswd.c" }|False)
                  --> ({ "ln": 349, "cl": 9, "fl": "auth_htpasswd.c" }|True)
                  --> ({ "ln": 360, "cl": 8, "fl": "auth_htpasswd.c" }|False)
                  --> ({ "ln": 360, "cl": 8, "fl": "auth_htpasswd.c" }|True)
                  --> ({ "ln": 370, "cl": 5, "fl": "auth_htpasswd.c" }|True)

误报，各if分支和390均有对应fclose，同样可能是认为while无限循环导致误判

---

PartialFileClose : file open location at : (CallICFGNode: { "ln": 729, "cl": 16, "fl": "fserve.c" })
                 conditional file close path:
                  --> ({ "ln": 738, "cl": 5, "fl": "fserve.c" }|True)

误报，779行有fclose，同样可能是738行while导致的

---

PartialFileClose : file open location at : (CallICFGNode: { "ln": 135, "cl": 18, "fl": "auth_htpasswd.c" })
                 conditional file close path:
                  --> ({ "ln": 146, "cl": 5, "fl": "auth_htpasswd.c" }|True)

误报，169行有fclose，同样可能是146行while导致的