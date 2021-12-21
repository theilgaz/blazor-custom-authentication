# Blazor Custom Authentication
 
## Genel Bakış: ASP.NET Core Güvenlik

ASP.NET Core, geliştiricilerin uygulamalarının güvenliğini kolayca yapılandırmasına olanak tanır. ASP.NET Core, kimlik doğrulama, yetkilendirme, veri koruma, HTTPS zorlama, app gizli anahtarları, XSRF/CSRF önleme ve CORS yönetimi gibi özelliklere sahiptir. Bu güvenlik özellikleri sayesinde sağlam ve güvenilir ASP.NET Core uygulamaları oluşturabilirsiniz.

## ASP.NET Core güvenlik özellikleri

ASP.NET Core, dahilikimlik servislerinin yanı sıra uygulamanızın güvenliğini sağlamak için birçok araç ve kütüphane ile birlikte kullanılabilir. Facebook, Twitter ve LinkedIn gibi üçüncü parti kimlik servislerini de kullanabilirsiniz. ASP.NET Core ile birlikte app gizli anahtarları aracılığıyla gizli bilgileri kod içerisine dahil etmeden uygulamanızın kimlik kontrolünü kolayca yönetebilirsiniz.

## Kimlik Doğrulama vs. Yetkilendirme (Authentication vs. Authorization)

Kimlik doğrulama (Authentication), bir kullanıcının sisteme, veritabanına, uygulamaya veya bir kaynağa bakılarak kimlik bilgilerinin karşılaştırıldığı bir süreçtir. Bilgileri eşleşirse, kimlik doğrulanır *(authentication)* ve yetkilendirme *(authorization)* işleminde verilen yetkileri doğrultusunda eylemleri gerçekleştirebilir. Yetkilendirme (Authorization), bir kullanıcının ne yapmasına izin verdiğini belirleyen süreci ifade eder.

Kimlik doğrulama (Authentication) **kullanıcıyı doğrular**.
Yetkilendirme (Authorization) **kullanıcının hangi eylemleri yapabileceğini** ifade eder.


## Başlarken 

### Yol Haritası
- [Proje oluştur](#proje-olustur)
    - [Kullanıcı sınıfı oluştur](#kullanici-sinifi-olustur)
    - [Giriş sayfası oluştur](#giris-sayfasi-olustur)
    - [SessionStorage/LocalStorage kurulumu](#storage-kurulumu)
        - [SessionStorage](#session-storage)
        - [LocalStorage](#local-storage)
        - [Storage Servis Aktivasyonu](#storage-aktivasyonu)
        - [Blazor App Host modelinin düzenlenmesi](#host-model)
- [Özel Authentication (CustomAuthenticationStateProvider) yapısının kodlanması](#ozel-authentication)
    - [1. Adım: Startup.cs / Program.cs değişiklikleri](#step1)
    - [2. Adım: AuthenticationStateProvider'dan Miras Alma](#step2)
    - [3. Adım: App.razor değişiklikleri](#step3)
- [Arayüzün hazırlanması](#arayuz)

<a id="proje-olustur"></a>
## Proje Oluştur 

Şimdi yeni bir ASP.NET Core Web Application - Blazor Server/WebAssembly App - .NET 6 projesi oluşturalım. 

<a id="kullanici-sinifi-olustur"></a>
### Kullanıcı sınıfı oluştur 

`User` modeli içerisinde `Username` ve `Password` alanlarını tutalım.

```
    public class User
    {
        public string Username { get; set; }

        public string Password { get; set; }
    }
```
<a id="giris-sayfasi-olustur"></a>
### Giriş sayfası oluştur

Kullanıcı girişi için `Login.razor` sayfasını oluşturalım.

```
    <EditForm Model="@user" OnValidSubmit="DoLogin">
    <div class="mb-3">
            <label for="exampleInputEmail1" class="form-label">Email address</label>
            <input type="email" class="form-control" id="exampleInputEmail1"  @bind="user.Username">
            <div id="emailHelp" class="form-text">We'll never share your email with anyone else.</div>
        </div>
        <div class="mb-3">
            <label for="exampleInputPassword1" class="form-label">Password</label>
            <input type="password" class="form-control" id="exampleInputPassword1" @bind="user.Password">
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
    </EditForm>

    @code {

        private User user;

        protected override Task OnInitializedAsync()
        {
            user = new User();
            return base.OnInitializedAsync();
        }

        private async Task<bool> DoLogin()
        {
            // Call API
            return await Task.FromResult(true);
        }

    }
```
<a id="storage-kurulumu"></a>
### SessionStorage/LocalStorage kurulumu

<a id="session-storage"></a>
#### SessionStorage

Line-of-business uygulamalarında en yaygın kullanılan kullanıcı oturum yaklaşımı session üzerinde kullanıcı bilgilerini tutmaktır. Bununla ilgili birçok yaklaşım ve çözüm bulunmaktadır. Bu örnekte Blazored imzalı SessionStorage paketiyle, kimlik bilgisi doğrulanan kullanıcının kısıtlı verisini oturum süresi boyunca tutarak kullanacağız.

- Kurulumu gerçekleştirmek için `NuGet Package Manager` içerisinde Blazored.SessionStorage yazarak arama yapıp en güncel versiyonu indirebilirsiniz.
- Veya .NET CLI üzerinden `dotnet add package Blazored.SessionStorage` komutu ile kurulumu yapabilirsiniz.

<a id="local-storage"></a>
#### LocalStorage
Kullanıcıları sabit, sınırları belirli, intranet, veya vpn ile erişim sağlanabilen bir uygulama geliştiriyorsanız `SessionStorage` yerine `LocalStorage` paketini tercih edebilirsiniz. 

Makalenin diğer tüm bölümlerinde **Session**, **session**, **_session** anahtar kelimelerini **Local**, **local**, **_local** olarak değiştirmeniz yeterli olacaktır.

*Örnek*: ``` SessionStorage sessionStorage ``` yerine ``` LocalStorage localStorage``` olacak.

<a id="storage-aktivasyonu"></a>
#### Storage Servis Aktivasyonu

Şimdi `Startup.cs` içerisindeki `ConfigureServices` metoduna veya `Program.cs` dosyasına gelerek servisimizi projemize dahil edelim.

**Startup.cs** için:

```
    services.AddBlazoredSessionStorage();
```

**Program.cs** için:

```
    builder.Services.AddBlazoredSessionStorage();
```
<a id="host-model"></a>
#### Blazor App Host modelinin düzenlenmesi

Uygulamanızda SessionStorage, LocalStorage gibi JavaScript aracılığı ile uygulama içeriğinde kullanacağınız bileşenleri, değişkenleri ve verileri yöneteceğiniz kütüphaneleri kullanırken uygulamanızın tamamen derlenmiş olması gerekiyor. [Daha fazlası için tıklayın](https://github.com/Blazored/LocalStorage#usage-blazor-server).

Projenizde `Pages` dizini altında yer alan `_Host.cshtml` sayfasını açarak uygulamanızın `render-mode` özelliğini `Server` olarak değiştirmelisiniz.

```
<component type="typeof(App)" render-mode="Server"/>
```
<a id="ozel-authentication"></a>
## Özel Authentication (CustomAuthenticationStateProvider) Oluşturma

ASP.NET Core AuthenticationMiddleware yapısını projemize dahil etmek için yapmamız gerekenleri 3 adımda ele alalım.

<a id="step1"></a>
## 1. Adım: Startup.cs / Program.cs değişiklikleri

Authentication Middleware yapısını projemize dahil ederek Authentication yapımızı inşa edebiliriz.

**Startup.cs** ve **Program.cs** için:

```
    app.UseAuthentication();
    app.UseAuthorization();
```

<a id="step2"></a>
## 2. Adım: AuthenticationStateProvider'dan Miras Alma

AuthenticationStateProvider sınıfını miras alarak yeni bir StateProvider sınıfı oluşturalım (`CustomAuthenticationStateProvider`).

```
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Components.Authorization;

    public class CustomAuthenticationStateProvider : AuthenticationStateProvider
    {
       
    }
```

`ISessionStorageService` arayüzünü sınıfımıza dahil edelim.

```
        private ISessionStorageService _sessionStorageService;

        public CustomAuthenticationStateProvider(ISessionStorageService sessionStorageService)
        {
            _sessionStorageService = sessionStorageService;
        }
```

AuthenticationStateProvider'ın GetAuthenticationStateAsync metodunu özelleştirelim.

```
        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var email = await _sessionStorageService.GetItemAsStringAsync("email");
            ClaimsIdentity identity = email != null
                ? new ClaimsIdentity(new[] {new Claim(ClaimTypes.Name, email)}, "basic_user")
                : new ClaimsIdentity();
            var user = new ClaimsPrincipal(identity);
            return await Task.FromResult(new AuthenticationState(user));
        }
```

Başarılı giriş yapılması durumunda kimliğinin doğrulanmasını sağlayalım.

```
        public void MarkAsAuthenticated(string email)
        {
            var identity = new ClaimsIdentity(new[] {new Claim(ClaimTypes.Name, email)}, "basic_user");
            var user = new ClaimsPrincipal(identity);
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(user)));
        }
```

Güvenli çıkış yapılması durumunda kimliğinin silinmesini sağlayalım.
```
        public void MarkAsLoggedOut()
        {
            _sessionStorageService.RemoveItemAsync("email");
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
        }
```



#### Servis Aktivasyonu

Şimdi `Startup.cs` içerisindeki `ConfigureServices` metoduna veya `Program.cs` dosyasına gelerek servisimizi projemize dahil edelim.

**Startup.cs** için:

```
    services.AddScoped<CustomAuthenticationStateProvider, CustomAuthenticationStateProvider>();
    services.AddScoped<AuthenticationStateProvider>(p => p.GetService<CustomAuthenticationStateProvider>());
```

**Program.cs** için:

```
    builder.Services.AddScoped<CustomAuthenticationStateProvider, CustomAuthenticationStateProvider>();
    builder.Services.AddScoped<AuthenticationStateProvider>(p => p.GetService<CustomAuthenticationStateProvider>());
```

<a id="step3"></a>
## 3. Adım: App.razor değişiklikleri

Uygulamanın izleyeceği rotayı yöneten `RouteView` ile kimlik doğrulama sonucu erişim sağlanan `AuthorizeView` yapılarının birleşimi olan `AuthorizeRouteView`, uygulamamızın varsayılan görünümünü oluşturmalı.

`Task<AuthenticationState>` kullanımı için `CascadingAuthenticationState`'in App komponentinde yer alması gerekiyor. [Daha fazlası için tıklayın](https://docs.microsoft.com/en-us/aspnet/core/blazor/security/?view=aspnetcore-6.0#expose-the-authentication-state-as-a-cascading-parameter).

```
<CascadingAuthenticationState>
    <Router AppAssembly="@typeof(App).Assembly">
        <Found Context="routeData">
            <AuthorizeRouteView RouteData="@routeData" DefaultLayout="@typeof(MainLayout)"/>
            <FocusOnNavigate RouteData="@routeData" Selector="h1"/>
        </Found>
        <NotFound>
                <PageTitle>Not found</PageTitle>
                <LayoutView Layout="@typeof(MainLayout)">
                    <p role="alert">Sorry, there's nothing at this address.</p>
                </LayoutView>
        </NotFound>
    </Router>
</CascadingAuthenticationState>    
```

<a id="arayuz"></a>
# Arayüzün hazırlanması

### AuthorizeView Komponenti

Authentication yapısında arayüzlerimizde kullanabileceğimiz AuthorizeView komponenti bulunuyor. Bu komponent içerisine 3 farklı etiket alabiliyor.

```
<AuthorizeView>
    <Authorized>
        Kullanıcı kimliği doğrulandığında gösterilecek alan.
    </Authorized>
    <NotAuthorized>
        Kullanıcı kimliği doğrulanmadığında gösterilecek alan.
    </NotAuthorized>
    <Authorizing>
        Asenkron olarak kimlik doğrulanırken gösterilecek alan.
    </Authorizing>
</AuthorizeView>
```

Herkesin görüntüleyebileceği fakat sadece giriş yapmış kullanıcıların özel olarak görüntüleyebileceği bir içerik varsa, bunu sayfa içerisinde AuthorizeView ve alt etiketlerini kullanarak sağlayabiliriz.

```
<AuthorizeView>
    <Authorized>
        <h1>Merhaba, @context.User.Identity.Name!</h1>
        <p>Bu içeriği sadece giriş yaptıysanız görüntüleyebilirsiniz.</p>
        <button @onclick="SecureMethod">Sadece Yetkili İşlem Butonu</button>
    </Authorized>
    <NotAuthorized>
        <h1>Yetki Hatası!</h1>
        <p>Giriş yapmadınız.</p>
    </NotAuthorized>
</AuthorizeView>

@code {
    private void SecureMethod() { ... }
}
```


### Authorize Attribute

`[Authorize]` attribute'ü eklenen sayfalar, sadece kimliği doğrulanan kişilerin görüntüleyebileceği sayfalardır.

### Sadece giriş yapan kullanıcıların görüntülemesi

```
@page "/"
@attribute [Authorize]

Bu sayfayı sadece giriş yaptıysanız görüntüleyebilirsiniz.
```

### Rol özelinde erişimi kısıtlı sayfaların görüntülenmesi

```
@page "/"
@attribute [Authorize(Roles = "admin, superuser")]

Bu sayfayı sadece admin veya superuser rolüne sahipseniz görüntüleyebilirsiniz.
```

### İlke özelinde erişimi kısıtlı sayfaların görüntülenmesi

```
@page "/"
@attribute [Authorize(Policy = "content-editor")]

Bu sayfayı sadece content-editor ilkesine sahipseniz görüntüleyebilirsiniz.
```

### Yetkisizlerin görüntüleyeceği içeriğin Router komponentinde düzenlenmesi

```
<CascadingAuthenticationState>
    <Router AppAssembly="@typeof(Program).Assembly">
        <Found Context="routeData">
            <AuthorizeRouteView RouteData="@routeData" 
                DefaultLayout="@typeof(MainLayout)">
                <NotAuthorized>
                    <h1>Üzgünüm</h1>
                    <p>Bu sayfaya erişmeye yetkiniz yoktur.</p>
                    <p>Farklı bir kullanıcı olarak oturum açmanız gerekebilir.</p>
                </NotAuthorized>
                <Authorizing>
                    <h1>Yetkilendirme devam ediyor.</h1>
                    <p>Bu içerik sadece yetkilendirme devam ederken görüntülenir.</p>
                </Authorizing>
            </AuthorizeRouteView>
        </Found>
        <NotFound>
            <LayoutView Layout="@typeof(MainLayout)">
                <h1>Üzgünüm</h1>
                <p>Bu adreste bir içerik bulunamadı.</p>
            </LayoutView>
        </NotFound>
    </Router>
</CascadingAuthenticationState>
```
