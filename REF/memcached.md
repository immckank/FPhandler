NeverFree : memory allocation at : (CallICFGNode: { "ln": 93, "cl": 11, "fl": "stats_prefix.c" })


源代码中，调用的stats_prefix_find将calloc出的pfs放入了一个哈希表暂存，并在最后统一清理，因此没有泄漏

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 118, "cl": 11, "fl": "stats_prefix.c" })

同上

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 107, "cl": 11, "fl": "stats_prefix.c" })

同上

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 820, "cl": 20, "fl": "storage.c" })
                 conditional free path:
                  --> ({ "ln": 824, "cl": 5, "fl": "storage.c" }|True)
                  --> ({ "ln": 865, "cl": 9, "fl": "storage.c" }|True)
                  --> ({ "ln": 867, "cl": 34, "fl": "storage.c" }|True)
                  --> ({ "ln": 867, "cl": 13, "fl": "storage.c" }|True)

误报，saber认为仅有一条复杂路径能保证st.page_data被释放，但事实上在853行就有对应的free操作，且不会被条件语句跳过。原因不明，或因复杂控制语句，如循环引起

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 37, "cl": 24, "fl": "slab_automove.c" })
                 conditional free path:
                  --> ({ "ln": 43, "cl": 9, "fl": "slab_automove.c" }|True)

saber认为只有a->window_data分配异常时，触发free(a)，才会正确释放资源，但实际上存在对应的释放函数slab_automove_free，且会在slab_mover.c中和slab_automove_init通过函数指针对应成对调用，不会泄露

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 44, "cl": 24, "fl": "slab_automove_extstore.c" })
                 conditional free path:
                  --> ({ "ln": 54, "cl": 9, "fl": "slab_automove_extstore.c" }|True)

同上类似，对应的释放函数为slab_automove_extstore_free，同样在slab_mover.c中通过函数指针对应成对调用

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 517, "cl": 18, "fl": "crawler.c" })
                 conditional free path:
                  --> ({ "ln": 531, "cl": 5, "fl": "crawler.c" }|True)

saber认为只有经过531行的while循环，assoc_get_iterator内部申请的iter才会被释放；但事实上589行对应的assoc_iterate_final中会进行释放，且该行不会被跳过

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 40, "cl": 22, "fl": "slab_automove.c" })

saber认为a->window_data永不释放，但实际上存在对应的释放函数slab_automove_free，且会在slab_mover.c中和slab_automove_init通过函数指针对应成对调用，不会泄露

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 47, "cl": 22, "fl": "slab_automove_extstore.c" })

同上类似，对应的释放函数为slab_automove_extstore_free，同样在slab_mover.c中通过函数指针对应成对调用

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 1557, "cl": 9, "fl": "items.c" })
                 conditional free path:
                  --> ({ "ln": 1565, "cl": 9, "fl": "items.c" }|False)
                  --> ({ "ln": 1573, "cl": 5, "fl": "items.c" }|True)

误报，严格来说会有abort造成的泄漏，但这里算误报，而且报出的路径本身有误。saber认为只有特定逻辑语句下cdata才会被释放，但实际上1630行就有对应free操作，只有个别逻辑触发abort()才会导致泄漏，或许是被复杂逻辑误导

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 225, "cl": 22, "fl": "restart.c" })
                 conditional free path:
                  --> ({ "ln": 238, "cl": 9, "fl": "restart.c" }|False)
                  --> ({ "ln": 238, "cl": 9, "fl": "restart.c" }|True)
                  --> ({ "ln": 248, "cl": 5, "fl": "restart.c" }|False)
                  --> ({ "ln": 248, "cl": 5, "fl": "restart.c" }|True)
                  --> ({ "ln": 251, "cl": 13, "fl": "restart.c" }|False)
                  --> ({ "ln": 251, "cl": 13, "fl": "restart.c" }|True)
                  --> ({ "ln": 248, "cl": 5, "fl": "restart.c" }|False)

误报，此处，saber打印了通向多条可能释放路径的控制流图节点，打印顺序较怪异，或许是对图进行了bfs打印。误判是因为saber无法理解复杂循环条件，认为248行循环可能一直执行导致资源始终不释放

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 4866, "cl": 24, "fl": "memcached.c" })

正报

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 164, "cl": 13, "fl": "crawler.c" })

误报，在对应的crawler_expired_finalize中会进行d的资源释放

---

PartialLeak : memory allocation at : (CallICFGNode: { "ln": 76, "cl": 22, "fl": "restart.c" })
                 conditional free path:
                  --> ({ "ln": 86, "cl": 9, "fl": "restart.c" }|False)
                  --> ({ "ln": 86, "cl": 9, "fl": "restart.c" }|True)
                  --> ({ "ln": 98, "cl": 9, "fl": "restart.c" }|False)
                  --> ({ "ln": 105, "cl": 9, "fl": "restart.c" }|False)

误报，不按上述路径会执行到abort()而没有free，严格来说会造成泄漏，不过这里还是算误报

---

NeverFree : memory allocation at : (CallICFGNode: { "ln": 1524, "cl": 50, "fl": "storage.c" })

正报，和memcached.c的4866行涉及的是同一个对象

---

Double Free : memory allocation at : (CallICFGNode: { "ln": 820, "cl": 20, "fl": "storage.c" })
                 double free path:
                  --> ({ "ln": 824, "cl": 5, "fl": "storage.c" }|True)
                  --> ({ "ln": 865, "cl": 9, "fl": "storage.c" }|True)
                  --> ({ "ln": 867, "cl": 34, "fl": "storage.c" }|True)
                  --> ({ "ln": 867, "cl": 13, "fl": "storage.c" }|True)

误报，原变量st.page_data会且只会在853行free一次，与路径无关，或许因复杂路径引起，上面有一个相似的PartialLeak误报

---

PartialFileClose : file open location at : (CallICFGNode: { "ln": 104, "cl": 10, "fl": "slabs.c" })
                 conditional file close path:
                  --> ({ "ln": 108, "cl": 9, "fl": "slabs.c" }|True)

源代码115行就有fclose且不会被跳过，除非fopen失败fp本身就是NULL；或许因为while嵌套单if的不常见语法导致saber误以为fclose在循环内，造成误报