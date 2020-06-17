#!/usr/bin/python

import broker
import select



ep = broker.Endpoint()
subscriber = ep.make_subscriber("vast/email")
ep.listen("127.0.0.1", 9999)

while(True):

    ## this will block until we have read-readiness on the file descriptor
    # print("wait ...")
    fd_sets = select.select([subscriber.fd()], [], [])
    # print ("go on...")
    if not fd_sets[0]:
        print("boom. this is the end.")

    (topic, data) = subscriber.get() #// we could also subscriber.poll() and handle array of messages
    received_event = broker.bro.Event(data)

    print("received on topic: {}    event name: {}    content: {}".format(topic, received_event.name(), received_event.args()))
