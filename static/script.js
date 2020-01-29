
// List Alerts - Toggle Expand Detailed Information
document.addEventListener('DOMContentLoaded', function() {
  let cardContents = document.getElementsByClassName('card-content');
  let cardFooters = document.getElementsByClassName('card-footer');
  let cardToggles = document.getElementsByClassName('card-toggle');
  let expandAlert = document.getElementById('expand-alerts');
  let collapseAlerts = document.getElementById('collapse-alerts');

  // Handle clicking dropdown for single alert
  for (let i = 0; i < cardToggles.length; i++) {
    cardToggles[i].addEventListener('click', e => {
      console.log(e.currentTarget.parentElement.parentElement);
      e.currentTarget.parentElement.parentElement.childNodes[7].classList.toggle('is-hidden');
      e.currentTarget.parentElement.parentElement.childNodes[11].classList.toggle('is-hidden');
    });
  }

  // Handle expand all click
  expandAlert.addEventListener('click', e => {
    for (let i = 0; i < cardContents.length; i++) {
      if (cardContents[i].classList.contains('is-hidden')) {
        cardContents[i].classList.remove('is-hidden');
      }
    }
    for (let i = 0; i < cardFooters.length; i++) {
      if (!cardFooters[i].classList.contains('is-hidden')) {
        cardFooters[i].classList.add('is-hidden');
      }
    }
  });

  // Handle collapse all click
  collapseAlerts.addEventListener('click', e => {
    for (let i = 0; i < cardContents.length; i++) {
      if (!cardContents[i].classList.contains('is-hidden')) {
        cardContents[i].classList.add('is-hidden');
      }
    }
    for (let i = 0; i < cardFooters.length; i++) {
      if (cardFooters[i].classList.contains('is-hidden')) {
        cardFooters[i].classList.remove('is-hidden');
      }
    }
  });

});

// Bulma Calendar for Past Search
document.addEventListener('DOMContentLoaded', function() {
  bulmaCalendar.attach('[type="datetime"]');
  bulmaClearBtn = document.getElementsByClassName("datetimepicker-clear-button");
  bulmaClearBtn[0].setAttribute('type', 'button');
});

// Top Navigation Active Tab
function set_active_tab(id) {
  var e = document.getElementById(id);
  e.className += "is-active ";
}

// Top Navigation Active Tab
document.addEventListener('DOMContentLoaded', function() {
  switch (location.pathname) {
    case "/":
      set_active_tab("dashboard-input");
      break;
    case "/list_alerts":
      set_active_tab("alarms-input");
      break;
    case "/list_rules":
      set_active_tab("rules-input");
      break;
    case "/past_search":
      set_active_tab("past-search-input");
      break;
  }
});
