// See https://aka.ms/new-console-template for more information
using BenchmarkDotNet.Running;


//var summary = BenchmarkRunner.Run(typeof(CryptoEx.Benchmark.Basic.Base64Url));
//var summary = BenchmarkRunner.Run(typeof(CryptoEx.Benchmark.EtsiXml.EcdsSignVerify));
var summary = BenchmarkRunner.Run(typeof(CryptoEx.Benchmark.Etsi.EcdsaSignVerify));