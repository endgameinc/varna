document.addEventListener('DOMContentLoaded', function() {
  let cardToggles = document.getElementsByClassName('card-toggle');
  for (let i = 0; i < cardToggles.length; i++) {
    cardToggles[i].addEventListener('click', e => {
      e.currentTarget.parentElement.parentElement.childNodes[3].classList.toggle('is-hidden');
    });
  }
});

document.addEventListener('DOMContentLoaded', function() {
  bulmaCalendar.attach('[type="datetime"]');
});

function set_active_tab(id) {
  var e = document.getElementById(id);
  e.className += "is-active ";
}

document.addEventListener('DOMContentLoaded', function() {
  console.log(location.pathname);
  switch (location.pathname) {
    case "/list_alarms":
      set_active_tab("alarms-input");
      break;
    case "/list_rules":
      set_active_tab("rules-input");
      break;
    case "/past_search":
      set_active_tab("past-search-input");
      breakl
  }
});
