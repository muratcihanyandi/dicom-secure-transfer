self.receiver_thread = FileReceiverThread(self)
self.receiver_thread.log_signal.connect(self.log_message)
self.receiver_thread.start()
