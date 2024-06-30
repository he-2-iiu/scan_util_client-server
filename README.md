# Malvare scan util client-server
Simple client-server app written as a test task for KasperskyLab. It tries to detect malvare scripts and other stuff. Scanner works with a pull of threads following a worker-crew model.
It recives files to scan from the scan_util and perform checks on them, returning results back to util.
