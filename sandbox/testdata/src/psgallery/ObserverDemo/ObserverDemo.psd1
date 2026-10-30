@{
    RootModule        = 'ObserverDemo.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b1c2d3e4-f5a6-4b7c-8d9e-0a1b2c3d4e5f'
    Author            = 'AegisProxy Sandbox Fixture'
    Description       = 'AegisProxy sandbox test fixture (harmless). Importing it runs init.ps1, which exercises the observers.'
    ScriptsToProcess  = @('init.ps1')
    FunctionsToExport = @('Get-ObserverDemo')
}
