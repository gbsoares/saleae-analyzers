# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
#
# SLIP decoder HLA for Saleae Logic 2
#
# Attach this HLA to an Async Serial analyzer. It will:
#   - Read decoded bytes from the serial analyzer
#   - Decode SLIP framing (0xC0, 0xDB escapes)
#   - Emit one AnalyzerFrame per SLIP packet

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame


END = 0xC0  # SLIP END
ESC = 0xDB  # SLIP ESC
ESC_END = 0xDC
ESC_ESC = 0xDD

PROTOCOL_NAMES = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}


class Hla(HighLevelAnalyzer):
    """
    SLIP High-Level Analyzer

    Input: Async Serial analyzer frames
      - frame.type == 'data'
      - frame.data['data'] is a bytearray / list of integers

    Output frames (UI-safe primitive types):
      - 'slip_packet': a decoded SLIP packet
      - 'slip_error' : error in SLIP stream (bad escape, etc)
      - 'ipv4_packet': decoded IPv4 packet inside SLIP
      - 'ipv4_error' : error decoding IPv4 packet
    """

    # What shows up in the bubble text / data table.
    # Keys here must match the frame types and data keys we emit.
    result_types = {
        'slip_packet': {
            'format': 'SLIP len={{data.length}}: {{data.payload_hex}}'
        },
        'slip_error': {
            'format': 'SLIP ERROR: {{data.message}} (byte=0x{{data.byte:02X}})'
        },
        'ipv4_packet': {
            'format': 'IPv4 [{{data.src}} -> {{data.dst}} {{data.protocol}} len={{data.total_length}}{{data.ports}}]'
        },
        'ipv4_error': {
            'format': 'IPv4 ERROR: {{data.message}}'
        },
    }

    def __init__(self):
        # Called once when the HLA is created
        self._reset_state()
        # Timing tracking (preserved across frames)
        self.first_frame_start = None
        self.last_frame_end = None

    def _reset_state(self):
        self.escape = False
        self.buffer = bytearray()
        self.frame_start_time = None
        # Note: first_frame_start and last_frame_end are NOT reset here

    @staticmethod
    def _byte_spans(frame):
        """
        Yield (byte_value, start_time, end_time) for each byte in the frame.

        Async Serial gives one start/end for the whole decoded chunk; to avoid
        SaleaeTime math errors, keep the same times for each byte.
        """
        values = list(frame.data.get('data', []))
        if not values:
            return []
        return [(b, frame.start_time, frame.end_time) for b in values]

    def _emit_packet_frame(self, end_time):
        """Create an AnalyzerFrame for the current SLIP packet, if any."""
        if not self.buffer:
            return None

        payload = list(self.buffer)  # Keep JSON-serializable data for Logic
        payload_hex = ' '.join(f'{b:02X}' for b in payload)

        f = AnalyzerFrame(
            'slip_packet',
            self.frame_start_time if self.frame_start_time else end_time,
            end_time,
            {
                # Keep frame data to primitive types Saleae accepts (no lists)
                'payload_hex': payload_hex,
                'length': len(payload),
            }
        )

        return f

    def _parse_ipv4(self, payload):
        """
        Decode the IPv4 header from the given payload.

        Returns (data_dict, error_str). If decoding fails, data_dict is None and
        error_str contains a human-readable message.
        """
        if len(payload) < 20:
            return None, 'Too short for IPv4 header'

        version = payload[0] >> 4
        ihl = payload[0] & 0x0F

        if version != 4:
            return None, f'Unsupported IP version {version}'

        header_length = ihl * 4
        if ihl < 5:
            return None, f'Invalid IHL (too small): {ihl}'
        if len(payload) < header_length:
            return None, f'Truncated IPv4 header (need {header_length}, have {len(payload)})'

        total_length = (payload[2] << 8) | payload[3]
        if total_length < header_length:
            return None, f'Total length smaller than header ({total_length} < {header_length})'
        if len(payload) < total_length:
            return None, f'Truncated IPv4 packet (total_length={total_length}, have {len(payload)})'

        src = '.'.join(str(b) for b in payload[12:16])
        dst = '.'.join(str(b) for b in payload[16:20])
        protocol_num = payload[9]
        protocol_name = PROTOCOL_NAMES.get(protocol_num, f'Proto {protocol_num}')

        ports = ''
        src_port = None
        dst_port = None
        transport_payload = None
        
        # Attempt to extract TCP/UDP ports and payload if applicable
        if protocol_num in (6, 17) and len(payload) >= header_length + 4:
            src_port = (payload[header_length] << 8) | payload[header_length + 1]
            dst_port = (payload[header_length + 2] << 8) | payload[header_length + 3]
            ports = f' {src_port} -> {dst_port}'
            
            # Extract transport layer payload (after TCP/UDP header)
            # TCP header is variable (min 20 bytes), UDP header is 8 bytes
            if protocol_num == 17:  # UDP
                udp_length = (payload[header_length + 4] << 8) | payload[header_length + 5]
                transport_header_len = 8
                if len(payload) >= header_length + transport_header_len:
                    transport_payload = payload[header_length + transport_header_len:total_length]
            elif protocol_num == 6:  # TCP
                if len(payload) >= header_length + 12:
                    tcp_data_offset = (payload[header_length + 12] >> 4) * 4
                    if len(payload) >= header_length + tcp_data_offset:
                        transport_payload = payload[header_length + tcp_data_offset:total_length]

        data = {
            'src': src,
            'dst': dst,
            'protocol': protocol_name,
            'total_length': str(total_length),
            'header_length': str(header_length),
            'payload_length': str(total_length - header_length),
            'ports': f' {src_port} -> {dst_port}' if src_port and dst_port else '',
            'transport_payload': str(transport_payload) if transport_payload else '',
        }

        return data, None

    def _print_transport_payload(self, parsed):
        """Print UDP/TCP payload to terminal."""
                
        src_ip = parsed.get('src')
        dst_ip = parsed.get('dst')
        src_port = parsed.get('ports').split(' -> ')[0].strip() if parsed.get('ports') else None
        dst_port = parsed.get('ports').split(' -> ')[1].strip() if parsed.get('ports') else None
        transport_payload = parsed.get('transport_payload')
        protocol_name = parsed.get('protocol')
        payload_length = parsed.get('payload_length')
        abs_time = parsed.get('abs_time', '')
        delta_time = parsed.get('delta_time', '')

        if not transport_payload or not src_port or not dst_port:
            return
        
        timing_info = f"[t={abs_time}s, dt={delta_time}s] " if abs_time else ""
        print(f"{timing_info}{src_ip}:{src_port} -> {dst_ip}:{dst_port} - {protocol_name} ({payload_length}): {transport_payload}")

    def _emit_ipv4_frame(self, start_time, end_time):
        """Create an AnalyzerFrame for the decoded IPv4 packet."""
        if not self.buffer:
            return None

        parsed, error = self._parse_ipv4(self.buffer)
        start = start_time if start_time else (self.frame_start_time if self.frame_start_time else end_time)

        if error:
            return AnalyzerFrame(
                'ipv4_error',
                start,
                end_time,
                {
                    'message': error,
                }
            )

        if not parsed:
            return None
        
        # Calculate timing information
        if self.first_frame_start is None:
            self.first_frame_start = start
        
        # Absolute time since first frame
        abs_time = float(start - self.first_frame_start)
        
        # Delta time from end of last frame to start of this frame
        if self.last_frame_end is not None:
            delta_time = float(start - self.last_frame_end)
        else:
            delta_time = 0.0
        
        # Update last frame end time
        self.last_frame_end = end_time
        
        # Add timing info to parsed data
        parsed['abs_time'] = f"{abs_time:.6f}"
        parsed['delta_time'] = f"{delta_time:.6f}"
        
        # Print UDP/TCP payload to terminal
        self._print_transport_payload(parsed)

        return AnalyzerFrame(
            'ipv4_packet',
            start,
            end_time,
            parsed
        )

    def _emit_error_frame(self, end_time, message, offending_byte):
        """Create an AnalyzerFrame for an error in the SLIP stream."""
        f = AnalyzerFrame(
            'slip_error',
            self.frame_start_time if self.frame_start_time else end_time,
            end_time,
            {
                'message': message,
                'byte': offending_byte,
            }
        )
        # After an error, reset the state machine
        self._reset_state()
        return f

    def decode(self, frame):
        """
        Called once per input frame from the Async Serial analyzer.

        We may:
          - Return None              -> no output
          - Return a single frame    -> AnalyzerFrame(...)
          - Return a list of frames  -> [AnalyzerFrame(...), ...]
        """
        # Debug: Print all public methods and attributes of the frame object
        # We only care about data frames from Async Serial.
        # Skip error frames (framing errors, parity errors, etc.)
        if frame.type != 'data':
            return None
        
        # Check if this frame has an error flag
        if frame.data.get('error'):
            return None

        out_frames = []

        for byte_val, byte_start, byte_end in self._byte_spans(frame):
            # Do not start a packet on a boundary END; wait for data
            if self.frame_start_time is None and byte_val != END:
                self.frame_start_time = byte_start

            if self.escape:
                # Previous byte was ESC; interpret this one specially
                if byte_val == ESC_END:
                    self.buffer.append(END)
                elif byte_val == ESC_ESC:
                    self.buffer.append(ESC)
                else:
                    # Invalid escape sequence
                    err = self._emit_error_frame(
                        byte_end,
                        'Invalid escape sequence after 0xDB',
                        byte_val
                    )
                    if err:
                        out_frames.append(err)
                self.escape = False
                continue

            # Not in escape mode
            if byte_val == ESC:
                # Next byte should be ESC_END or ESC_ESC
                self.escape = True
                if self.frame_start_time is None:
                    self.frame_start_time = byte_start
                continue

            if byte_val == END:
                # END marks the end of the current SLIP packet
                packet_start = self.frame_start_time if self.frame_start_time else byte_end
                
                # Try to decode as IPv4; if that fails, emit the raw SLIP packet
                ipv4_frame = self._emit_ipv4_frame(packet_start, byte_end)
                if ipv4_frame:
                    out_frames.append(ipv4_frame)
                else:
                    # No valid IPv4, emit raw SLIP packet
                    packet = self._emit_packet_frame(byte_end)
                    if packet:
                        out_frames.append(packet)
                
                # Clear state and wait for the next packet (also handles empty packets)
                self._reset_state()
                continue

            # Regular data byte
            self.buffer.append(int(byte_val) & 0xFF)

        if not out_frames:
            return None
        return out_frames
