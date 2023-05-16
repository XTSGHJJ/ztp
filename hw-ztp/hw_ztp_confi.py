import ops 


_ops=ops.cli()
handle, err_desp= _ops.open()
choice = {"Continue": "y", "save": "n"}
_ops.execute(handle,"system-view immediately")
_ops.execute(handle,"sysname test")
ret = _ops.close(handle)
print 'test_info ='
