// See https://aka.ms/new-console-template for more information
using BenchmarkDotNet.Running;


var summary = BenchmarkRunner.Run(typeof(EdDSA.Benchmark.Basic.Base64Url));