-module(edge_core_pcap_replay).

-compile([{parse_transform, lager_transform}]).

-define(IPV4_DATAGRAM, 2048).
-define(UDP, 17).
-define(TCP, 6).
-define(ICMP, 1).

-record(state, {last_packet, packet_count, receiver}).

-record(transport_data, {
         source_port,
         destination_port,
         type,
         data}).

-record(packet, {
         timestamp,
         packet_type,
         source_ip,
         destination_ip,
         transport_data
         }).

%% API
-export([decode/2]).

%% @doc decodes dns-requests from pcap dump and sends them as erlang messages to a receiver process.
decode(Path, Receiver) ->
    case file:open(Path, [read, raw, binary]) of
        {ok, File} ->
            ok = verify_global_header(File),
            {ok, #packet { timestamp = Timestamp }} = decode_packet(File),
            InitialState = #state { packet_count = 0,
                                    last_packet  = Timestamp,
                                    receiver     = Receiver },
            decode_packet_stream(File, InitialState);
  
        {error, Reason} ->
          {error, Reason}
    end.

%% @private
decode_packet_stream(File, #state { packet_count = Count,
                                    receiver     = Receiver,
                                    last_packet  = LastTimestamp } = State) ->
    case decode_packet(File) of
        {ok, #packet { source_ip      = SourceIP,
                       timestamp      = Timestamp,
                       transport_data = #transport_data { type             = udp,
                                                          data             = Data,
                                                          source_port      = SourcePort,
                                                          destination_port = 53 }}} ->

            Receiver ! {udp, undefined, SourceIP, SourcePort, Data},
            sleep(Timestamp, LastTimestamp),
            decode_packet_stream(File, State#state { last_packet  = Timestamp,
                                                     packet_count = Count + 1});

        {ok, #packet { timestamp = Timestamp }} ->
            sleep(Timestamp, LastTimestamp),
            decode_packet_stream(File, State#state { last_packet  = Timestamp,
                                                     packet_count = Count + 1});

        no_more_packets ->
            lager:notice("Finished relaying. ~p packets processed.", [Count]),
            ok
    end.


%% @private
decode_packet(File) ->
    case decode_pcap_packet(File) of
        {ok, {TimestampSeconds, TimestampMicroSeconds, _Size, Esize}} ->
            {ok, {_SourceMAC, _DestinationMAC, EtherType, Payload}} = decode_ethernet_frame(
                                                                      File, Esize),
            {ok, {TransportProtocol, SourceIP, DestinationIP, Data}} = decode_network_packet(
                                                                         EtherType, Payload),
            {ok, TransportData} = decode_transport_packet(TransportProtocol, Data),
            TimeStamp = TimestampSeconds * 1000000 + TimestampMicroSeconds,
            Packet = #packet { timestamp             = TimeStamp,
                               transport_data        = TransportData,
                               packet_type           = fixme,
                               source_ip             = SourceIP,
                               destination_ip        = DestinationIP},
            {ok, Packet};
        no_more_packets ->
            file:close(File),
            no_more_packets
    end.

%% @private
verify_global_header(File) ->
  case file:read(File, 24) of
    {ok, <<16#d4, 16#c3, 16#b2, 16#a1, _Header/binary>>} ->
          ok;
    {ok, Other} ->
          lager:error("Improper pcap header: ~p", [Other]),
          error
  end.


%% @private
decode_pcap_packet(File) ->
    case file:read(File, 16) of
      {ok, <<TimestampSeconds:32/little,
             TimestampMicroSeconds:32/little,
             Size:32/little, % size of packet FIXME is this really
             Esize:32/little>>} -> % size of captured data
          {ok, {TimestampSeconds, TimestampMicroSeconds, Size, Esize}};
      eof ->
            no_more_packets;
      Other ->
            lager:error("Unable to parse pcap packet: ~p", [Other]),
            error
    end.


%% @private
decode_ethernet_frame(File, Size) ->
    case file:read(File, Size) of
        {ok, <<SourceAddress:48,
               DestinationAddress:48,
               EtherType:16,
               Data/binary>>} ->
            {ok, {SourceAddress, DestinationAddress, EtherType, Data}};
        Other ->
            lager:error("Unable to parse ethernet frame: ~p", [Other])
    end.


%% @private
decode_network_packet(?IPV4_DATAGRAM, 
                      <<4:4, _IHL:4, _DSCP:6, _ECN:2, _TotalLength:16,
                        _ID:16, _Flags:3, _FragmentOffset:13, _TTL:8,
                        TransportProtocol:8, _Checksum:16,
                        SourceIP:4/binary, DestinationIP:4/binary, Data/binary>>) ->
    {ok, {TransportProtocol, decode_ip(SourceIP), decode_ip(DestinationIP), Data}};

decode_network_packet(EtherType, _Data) -> 
    lager:warning("Unkown/unsupported EtherType ~p", [EtherType]),
    error.


%% @private
decode_transport_packet(?UDP, <<SourcePort:16, DestinationPort:16,
                                _Length:16, _Checksum:16, Data/binary>>) ->
  TransportData = #transport_data {
                     type             = udp,
                     source_port      = SourcePort,
                     destination_port = DestinationPort,
                     data             = Data}, 
  {ok, TransportData};

decode_transport_packet(?TCP, <<_SourcePort:16, _DestinationPort:16, _SequenceNumber:32,
                            _Ack:32, _Offset:4, _Reserved:3, _Flags:9, _Windowsize:16,
                            _Cheksum:16, _Urgent:16, _Rest/binary>>) ->
  {ok, unsupported};

decode_transport_packet(?ICMP, _ICMPData) ->
  {ok, unsupported};

decode_transport_packet(Protocol, _) ->
  lager:warning("Unkown transport protocol ~p", [Protocol]),
  {ok, unsupported}.

%% @private
sleep(Timestamp, LastTimestamp) ->
    TimestampMiliseconds = (Timestamp - LastTimestamp) / 1000,
    timer:sleep(erlang:round(TimestampMiliseconds)).

%% @private
decode_ip(<<A:8/integer, B:8/integer, C:8/integer, D:8/integer>>) ->
    {A, B, C, D}.
