using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO.Pipelines;

namespace virus_scanner
{
    class Scanner {
        MemoryReader _memoryReader;

        Pipe _pipe;
        PipeReader _reader;
        PipeWriter _writer;

        public Scanner(MemoryReader memory) {
            _memoryReader = memory;
            
            _pipe = new Pipe();
            _reader = _pipe.Reader;
            _writer = _pipe.Writer;
        }

        public int MinimumBufferSize { get; } = Environment.SystemPageSize;

        public PipeReader Reader { get => _reader; }

        public async Task<List<IntPtr>> ScanForByteArray(IntPtr address, int size, byte[] needle, CancellationToken cancellation = default) {
            var reading = FillPipe(address, size, cancellation);
            var results = new List<IntPtr>();
        
            while (!cancellation.IsCancellationRequested)
            {
                ReadResult result = await _reader.ReadAsync();

                ReadOnlySequence<byte> buffer = result.Buffer;
                SequencePosition? position = null;

                do 
                {
                    if (buffer.FirstSpan.StartsWith(needle)) {
                        results.Add(address);
                    }

                    address = IntPtr.Add(address, 1);
                    Reader.AdvanceTo(buffer.GetPosition(1));
                }
                while (position != null);

                if (result.IsCompleted)
                    break;
            }

            _reader.Complete();
            return results;
        }

        private async Task FillPipe(IntPtr address, int size, CancellationToken cancellation = default) {
            if (!_memoryReader.IsProcessOpen)
                throw new InvalidOperationException("Process must be opened before memory reading can occur!");
                
            while (!cancellation.IsCancellationRequested)
            {
                Memory<byte> memory = _writer.GetMemory(MinimumBufferSize);

                try 
                {
                    var toRead = Math.Min(size, MinimumBufferSize);
                    var bytesRead = _memoryReader.TryReadBytes(address, toRead, memory);

                    if (bytesRead == 0)
                        break;

                    _writer.Advance(bytesRead);
                    size -= memory.Length;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(ex);
                    break;
                }

                var result = await _writer.FlushAsync();
                if (result.IsCompleted)
                    break;
            }

            _writer.Complete();
        }
    }
}