using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PSOBB.Launcher.Models;
using PSOBB.Launcher.Services;

namespace PSOBB.Launcher.Tests;

[TestClass]
public sealed class LifecycleApiCompatibilityTests
{
    [TestMethod]
    public void LifecycleApis_PreserveLegacyCancellationAndAddExplicitEnvironmentOverloads()
    {
        Assert.IsNotNull(
            typeof(RuntimeLifecycleObserver).GetConstructor([typeof(LoopbackHealthProbe)]),
            "The public RuntimeLifecycleObserver(LoopbackHealthProbe) constructor is missing.");

        foreach (var type in new[] { typeof(LifecycleScriptController), typeof(LauncherCoordinator) })
        {
            AssertOverload(type, "ObserveAsync", typeof(string), typeof(CancellationToken));
            AssertOverload(
                type,
                "ObserveAsync",
                typeof(string),
                typeof(ServerEnvironmentKind),
                typeof(CancellationToken));
            foreach (var methodName in new[]
            {
                "StartServerAsync",
                "StopClientAsync",
                "StopServerAsync",
                "StopAllAsync",
            })
            {
                AssertOverload(type, methodName, typeof(string), typeof(CancellationToken));
                AssertOverload(
                    type,
                    methodName,
                    typeof(string),
                    typeof(ServerEnvironmentKind),
                    typeof(CancellationToken));
            }

            foreach (var methodName in new[]
            {
                type == typeof(LifecycleScriptController) ? "PlayAsync" : "StartSessionAsync",
                "StartClientAsync",
                "RepairClientAsync",
            })
            {
                AssertOverload(
                    type,
                    methodName,
                    typeof(string),
                    typeof(LifecycleSelection),
                    typeof(CancellationToken));
                AssertOverload(
                    type,
                    methodName,
                    typeof(string),
                    typeof(LifecycleSelection),
                    typeof(ServerEnvironmentKind),
                    typeof(CancellationToken));
            }
        }

        AssertOverload(
            typeof(ILifecycleStateObserver),
            "ObserveAsync",
            typeof(string),
            typeof(CancellationToken));
        AssertOverload(
            typeof(ILifecycleStateObserver),
            "ObserveAsync",
            typeof(string),
            typeof(ServerEnvironmentKind),
            typeof(CancellationToken));
    }

    private static void AssertOverload(Type type, string name, params Type[] parameterTypes)
    {
        var match = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .SingleOrDefault(method => method.Name == name
                && method.GetParameters().Select(parameter => parameter.ParameterType)
                    .SequenceEqual(parameterTypes));
        Assert.IsNotNull(
            match,
            $"{type.Name}.{name}({string.Join(", ", parameterTypes.Select(value => value.Name))}) is missing.");
    }
}
